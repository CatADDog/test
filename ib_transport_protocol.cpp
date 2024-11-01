/************************************************
Copyright (c) 2019, Systems Group, ETH Zurich.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
************************************************/

#include "ib_transport_protocol.hpp"
#include "rocev2_config.hpp"
#include "conn_table.hpp"
#include "state_table.hpp"
#include "msn_table.hpp"
#include "transport_timer.hpp"
#include "retransmitter/retransmitter.hpp"
#include "read_req_table.hpp"
#include "multi_queue/multi_queue.hpp"
#include "cauchy_coding/gf256.h"
#include "cauchy_coding/MyError.h"

/*
函数概述
rx_exh_fsm 是一个状态机函数，用于根据输入的 RDMA 基本头部和扩展头部信息，处理不同的 RDMA 操作。它将 RDMA 扩展头部解析后，根据操作类型生成对应的读写命令，或更新必要的状态信息。

输入参数
metaIn: 存放 IB 基本头部的元数据，包含目标 QP 编号、操作码、PSN 等。
udpLengthFifo: 存储 UDP 数据包的长度。
msnTable2rxExh_rsp: 从 MSN 表格中读取的数据，包含关于数据块的传输状态等信息。
headerInput: 读取的 RDMA 扩展头部（RETH、AETH 等）。
memoryWriteCmd: 用于发出内存写入命令。
readRequestFifo: 生成的读取请求会被写入这个流。
rxExh2msnTable_upd_req: 更新 MSN 表格的请求。
readReqTable_upd_req: 更新读请求表格的请求。
rx_exhEventMetaFifo: ACK 事件元数据输出流。
rx_pkgSplitTypeFifo: 包拆分类型，决定如何处理后续的数据。
rx_pkgShiftTypeFifo: 数据包偏移的类型。
状态机的实现
状态机实现为一个三状态的 FSM：

META: 处理元数据。
DMA_META: 处理 DMA 相关的元数据。
DATA: 处理数据本身。
状态机各状态解析
META 状态

从 metaIn 和 headerInput 中读取基本头部和扩展头部信息。
根据操作码检查是否需要进行后续操作（例如读取地址、更新 MSN 表等）。
主要目的是准备处理数据的上下文信息，并准备进入 DMA_META 状态。
DMA_META 状态

在该状态中，FSM 读取与 DMA 相关的元数据，包括 MSN 表的数据（msnTable2rxExh_rsp）、UDP 长度（udpLengthFifo）以及读取请求表（readReqTable_rsp，仅在启用重传时使用）。
如果操作码是读取响应，则会请求读取所需的地址。
该状态的目的是准备进行具体的内存操作和数据传输操作，随后进入 DATA 状态。
DATA 状态

根据操作码类型，FSM 执行不同的数据处理操作，包括内存写入、读取请求生成、ACK 触发等。
具体操作码处理：
RDMA Write Only / First / Middle / Last:
处理写操作，生成内存写入请求（使用 memoryWriteCmd）。
根据数据长度和虚拟地址更新 MSN 表。
写操作结束后，会生成 ACK 确认。
RDMA Read Request / Consistent Read Request:
处理读请求，生成对应的读取请求并发送至 readRequestFifo。
更新 MSN 表。
RDMA Read Response:
处理读响应，提取 ACK 扩展头部（AETH）。
如果 AETH 表示 NAK，则请求重传（通过 rx2retrans_req）。
否则，更新读请求表。
如果是最后一个响应，还会发出内存写入命令。
ACK:
处理 ACK 扩展头部。
如果 ACK 是 NAK，或读请求超时未完成，则触发重传。
*/
template <int WIDTH>
void rx_exh_fsm(stream<ibhMeta> &metaIn,
				stream<ap_uint<16>> &udpLengthFifo,
				stream<dmaState> &msnTable2rxExh_rsp,
#if RETRANS_EN
				stream<rxReadReqRsp> &readReqTable_rsp,
#endif
				stream<ap_uint<64>> &rx_readReqAddr_pop_rsp,
				stream<ExHeader<WIDTH>> &headerInput,
				stream<routedMemCmd> &memoryWriteCmd,
				stream<readRequest> &readRequestFifo,
#if POINTER_CHASING_EN
				stream<ptrChaseMeta> &m_axis_rx_pcmeta,
#endif
				stream<rxMsnReq> &rxExh2msnTable_upd_req,
				// #if RETRANS_EN
				stream<rxReadReqUpdate> &readReqTable_upd_req,
				// #endif
				stream<mqPopReq> &rx_readReqAddr_pop_req,
				stream<ackEvent> &rx_exhEventMetaFifo,
#if RETRANS_EN
				stream<retransmission> &rx2retrans_req,
#endif
				stream<pkgSplitType> &rx_pkgSplitTypeFifo,
				stream<pkgShiftType> &rx_pkgShiftTypeFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"rx_exh_fsm 函数开始执行"<<std::endl;
	enum pe_fsmStateType
	{
		META,
		DMA_META,
		DATA
	};
	static pe_fsmStateType pe_fsmState = META;
	static ibhMeta meta;
	net_axis<WIDTH> currWord;
	static ExHeader<WIDTH> exHeader;
	static dmaState dmaMeta;
	static ap_uint<16> udpLength;
	ap_uint<32> payLoadLength;
	static bool consumeReadAddr;
	static rxReadReqRsp readReqMeta;
	static ap_uint<64> readReqAddr;

	switch (pe_fsmState)
	{
	case META:
		if (!metaIn.empty() && !headerInput.empty())
		{
			metaIn.read(meta);
			headerInput.read(exHeader);

			rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp));
			consumeReadAddr = false;
#if RETRANS_EN1
			if (meta.op_code == RC_ACK)
			{
				readReqTable_upd_req.write(rxReadReqUpdate(meta.dest_qp));
			}
#endif
			if (meta.op_code == RC_RDMA_READ_RESP_ONLY || meta.op_code == RC_RDMA_READ_RESP_FIRST)
			{
				consumeReadAddr = true;
				rx_readReqAddr_pop_req.write(mqPopReq(meta.dest_qp));
			}
			pe_fsmState = DMA_META;
		}
		break;
	case DMA_META:
#if !(RETRANS_EN)
		if (!msnTable2rxExh_rsp.empty() && !udpLengthFifo.empty() && (!consumeReadAddr || !rx_readReqAddr_pop_rsp.empty()))
#else
		if (!msnTable2rxExh_rsp.empty() && !udpLengthFifo.empty() && (!consumeReadAddr || !rx_readReqAddr_pop_rsp.empty()) && (meta.op_code != RC_ACK || !readReqTable_rsp.empty()))
#endif
		{
			msnTable2rxExh_rsp.read(dmaMeta);
			udpLengthFifo.read(udpLength);
#if RETRANS_EN
			if (meta.op_code == RC_ACK)
			{
				readReqTable_rsp.read(readReqMeta);
			}
#endif
			if (consumeReadAddr)
			{
				rx_readReqAddr_pop_rsp.read(readReqAddr);
			}
			pe_fsmState = DATA;
		}
		break;
	case DATA: // TODO merge with DMA_META
		switch (meta.op_code)
		{
		case RC_RDMA_WRITE_ONLY:
		// case RC_RDMA_WRITE_ONLY_WIT_IMD:
		case RC_RDMA_WRITE_FIRST:
		case RC_RDMA_PART_ONLY:
		case RC_RDMA_PART_FIRST:
		{
			// [BTH][RETH][PayLd]
			RdmaExHeader<WIDTH> rdmaHeader = exHeader.getRdmaHeader();
			axiRoute route = ((meta.op_code == RC_RDMA_WRITE_ONLY) || (meta.op_code == RC_RDMA_WRITE_FIRST)) ? ROUTE_DMA : ROUTE_CUSTOM;

			if (rdmaHeader.getLength() != 0)
			{
				// Compute payload length
				payLoadLength = udpLength - (8 + 12 + 16 + 4); // UDP, BTH, RETH, CRC
				// compute remaining length
				ap_uint<32> headerLen = rdmaHeader.getLength();
				ap_uint<32> remainingLength = headerLen - payLoadLength;

				// Send write request
				if ((meta.op_code == RC_RDMA_WRITE_ONLY) || (meta.op_code == RC_RDMA_WRITE_FIRST))
				{
					memoryWriteCmd.write(routedMemCmd(rdmaHeader.getVirtualAddress(), payLoadLength, route));
				}
				else if ((meta.op_code == RC_RDMA_PART_FIRST || (meta.op_code == RC_RDMA_PART_ONLY)))
				{
					memoryWriteCmd.write(routedMemCmd(rdmaHeader.getVirtualAddress(), headerLen, route));
				}
				// Update state
				// TODO msn, only for ONLY??
				rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn + 1, rdmaHeader.getVirtualAddress() + payLoadLength, remainingLength));
				// Trigger ACK
				rx_exhEventMetaFifo.write(ackEvent(meta.dest_qp)); // TODO does this require PSN??
				// std::cout << std::hex << "LEGNTH" << header.getLength() << std::endl;
				rx_pkgSplitTypeFifo.write(pkgSplitType(meta.op_code, route));
				rx_pkgShiftTypeFifo.write(SHIFT_RETH);
				pe_fsmState = META;
			}
			break;
		}
		case RC_RDMA_WRITE_MIDDLE:
		case RC_RDMA_WRITE_LAST:
		case RC_RDMA_PART_MIDDLE:
		case RC_RDMA_PART_LAST:
		{
			// [BTH][PayLd]
			/*std::cout << "PROCESS_EXH: ";
			print(std::cout, currWord);
			std::cout << std::endl;*/

			// Fwd data words
			axiRoute route = ((meta.op_code == RC_RDMA_WRITE_MIDDLE) || (meta.op_code == RC_RDMA_WRITE_LAST)) ? ROUTE_DMA : ROUTE_CUSTOM;
			payLoadLength = udpLength - (8 + 12 + 4); // UDP, BTH, CRC
			// compute remaining length
			ap_uint<32> remainingLength = dmaMeta.dma_length - payLoadLength;
			// Send write request
			if ((meta.op_code == RC_RDMA_WRITE_MIDDLE) || (meta.op_code == RC_RDMA_WRITE_LAST))
			{
				memoryWriteCmd.write(routedMemCmd(dmaMeta.vaddr, payLoadLength, route));
			}
			/*else if ((meta.op_code == RC_RDMA_PART_MIDDLE) || (meta.op_code == RC_RDMA_PART_LAST))
			{
				memoryWriteCmd.write(routedMemCmd(dmaMeta.vaddr, payLoadLength, route));
			}*/
			// TODO msn only on LAST??
			rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn + 1, dmaMeta.vaddr + payLoadLength, remainingLength));
			// Trigger ACK
			rx_exhEventMetaFifo.write(ackEvent(meta.dest_qp)); // TODO does this require PSN??
			rx_pkgSplitTypeFifo.write(pkgSplitType(meta.op_code, route));
			rx_pkgShiftTypeFifo.write(SHIFT_NONE);
			pe_fsmState = META;

#ifndef __SYNTHESIS__
			if ((meta.op_code == RC_RDMA_WRITE_LAST) || (meta.op_code == RC_RDMA_PART_LAST))
			{
				assert(remainingLength == 0);
			}
#endif
			break;
		}
		/*case RC_RDMA_WRITE_LAST_WITH_IMD:
			//TODO sth ;) fire interrupt
			break;*/
		case RC_RDMA_READ_REQUEST:
		case RC_RDMA_READ_CONSISTENT_REQUEST:
		{
			// [BTH][RETH]
			RdmaExHeader<WIDTH> rdmaHeader = exHeader.getRdmaHeader();
			if (rdmaHeader.getLength() != 0)
			{
				axiRoute route = (meta.op_code == RC_RDMA_READ_CONSISTENT_REQUEST) ? ROUTE_CUSTOM : ROUTE_DMA;
				readRequestFifo.write(readRequest(meta.dest_qp, rdmaHeader.getVirtualAddress(), rdmaHeader.getLength(), meta.psn, route));
				rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn + 1));
			}
			pe_fsmState = META;
			break;
		}
#if POINTER_CHASING_EN
		case RC_RDMA_READ_POINTER_REQUEST:
		{
			// [BTH][RPCH]
			RdmaPointerChaseHeader<WIDTH> pcHeader = exHeader.getPointerChasingHeader();
			if (pcHeader.getLength() != 0)
			{
				readRequestFifo.write(readRequest(meta.dest_qp, pcHeader.getVirtualAddress(), pcHeader.getLength(), meta.psn, ROUTE_CUSTOM));
				m_axis_rx_pcmeta.write(ptrChaseMeta(pcHeader.getPredicateKey(), pcHeader.getPredicateMask(), pcHeader.getPredicateOp(), pcHeader.getPtrOffset(), pcHeader.getIsRelPtr(), pcHeader.getNextPtrOffset(), pcHeader.getNextPtrValid()));
				rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn + 1));
			}
			pe_fsmState = META;
			break;
		}
#endif
		case RC_RDMA_READ_RESP_ONLY:
		case RC_RDMA_READ_RESP_FIRST:
		case RC_RDMA_READ_RESP_LAST:
		{
			// [BTH][AETH][PayLd]
			// AETH for first and last
			AckExHeader<WIDTH> ackHeader = exHeader.getAckHeader();
			if (ackHeader.isNAK())
			{
				// Trigger retransmit
#if RETRANS_EN
				rx2retrans_req.write(retransmission(meta.dest_qp, meta.psn));
#endif
			}
			else
			{
				readReqTable_upd_req.write((rxReadReqUpdate(meta.dest_qp, meta.psn)));
			}
			// Write out meta
			payLoadLength = udpLength - (8 + 12 + 4 + 4); // UDP, BTH, AETH, CRC
			rx_pkgShiftTypeFifo.write(SHIFT_AETH);
			if (meta.op_code != RC_RDMA_READ_RESP_LAST)
			{
				memoryWriteCmd.write(routedMemCmd(readReqAddr, payLoadLength));
				// TODO maybe not the best way to store the vaddr in the msnTable
				rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn, readReqAddr + payLoadLength, 0));
			}
			else
			{
				memoryWriteCmd.write(routedMemCmd(dmaMeta.vaddr, payLoadLength));
			}
			rx_pkgSplitTypeFifo.write(pkgSplitType(meta.op_code));
			pe_fsmState = META;
			break;
		}
		case RC_RDMA_READ_RESP_MIDDLE:
			// [BTH][PayLd]
			payLoadLength = udpLength - (8 + 12 + 4); // UDP, BTH, CRC
			rx_pkgShiftTypeFifo.write(SHIFT_NONE);
			memoryWriteCmd.write(routedMemCmd(dmaMeta.vaddr, payLoadLength));
			// TODO how does msn have to be handled??
			rxExh2msnTable_upd_req.write(rxMsnReq(meta.dest_qp, dmaMeta.msn + 1, dmaMeta.vaddr + payLoadLength, 0));
			rx_pkgSplitTypeFifo.write(pkgSplitType(meta.op_code));
			pe_fsmState = META;
			break;
		case RC_ACK:
		{
			// [BTH][AETH]
			AckExHeader<WIDTH> ackHeader = exHeader.getAckHeader();
			std::cout << "syndrome: " << ackHeader.getSyndrome() << std::endl;
#if RETRANS_EN
			if (ackHeader.isNAK())
			{
				// Trigger retransmit
				rx2retrans_req.write(retransmission(meta.dest_qp, meta.psn));
			}
			else if (readReqMeta.oldest_outstanding_readreq < meta.psn && readReqMeta.valid)
			{
				// Trigger retransmit
				rx2retrans_req.write(retransmission(meta.dest_qp, readReqMeta.oldest_outstanding_readreq));
			}
#endif
			pe_fsmState = META;
			break;
		}
		default:
			break;
		} // switch meta_Opcode
		break;
	} // switch
}

template <int WIDTH>
void rx_exh_payload(stream<pkgSplitType> &metaIn,
					stream<net_axis<WIDTH>> &input,
					stream<routed_net_axis<WIDTH>> &rx_exh2rethShiftFifo,
					stream<net_axis<WIDTH>> &rx_exh2aethShiftFifo,
					stream<routed_net_axis<WIDTH>> &rx_exhNoShiftFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"rx_exh_payload 函数开始执行"<<std::endl;
	enum fsmStateType
	{
		META,
		PKG
	};
	static fsmStateType rep_state = META;
	static pkgSplitType meta;

	net_axis<WIDTH> currWord;

	switch (rep_state)
	{
	case META:
		if (!metaIn.empty())
		{
			metaIn.read(meta);
			rep_state = PKG;
		}
		break;
	case PKG:
		if (!input.empty())
		{
			input.read(currWord);

			if (checkIfRethHeader(meta.op_code))
			{
				std::cout << "EXH PAYLOAD:";
				print(std::cout, currWord);
				std::cout << std::endl;
				rx_exh2rethShiftFifo.write(routed_net_axis<WIDTH>(currWord, meta.route));
			}
			else if ((meta.op_code == RC_RDMA_READ_RESP_ONLY) || (meta.op_code == RC_RDMA_READ_RESP_FIRST) ||
					 (meta.op_code == RC_RDMA_READ_RESP_LAST))
			{
				rx_exh2aethShiftFifo.write(currWord);
			}
			else
			{
				rx_exhNoShiftFifo.write(routed_net_axis<WIDTH>(currWord, meta.route));
			}

			if (currWord.last)
			{
				rep_state = META;
			}
		}
		break;
	} // switch
}

void handle_read_requests(stream<readRequest> &requestIn,
						  stream<memCmdInternal> &memoryReadCmd,
						  stream<event> &readEventFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"handle_read_requests 函数开始执行"<<std::endl;
	enum hrr_fsmStateType
	{
		META,
		GENERATE
	};
	static hrr_fsmStateType hrr_fsmState = META;
	static readRequest request; // Need QP, dma_length, vaddr
	static txMeta writeMeta;
	ibOpCode readOpcode;
	ap_uint<48> readAddr;
	ap_uint<32> readLength;
	ap_uint<32> dmaLength;

	switch (hrr_fsmState)
	{
	case META:
		if (!requestIn.empty())
		{
			requestIn.read(request);
			readAddr = request.vaddr;
			readLength = request.dma_length;
			dmaLength = request.dma_length;
			readOpcode = RC_RDMA_READ_RESP_ONLY;
			if (request.dma_length > PMTU)
			{
				readLength = PMTU;
				request.vaddr += PMTU;
				request.dma_length -= PMTU;
				readOpcode = RC_RDMA_READ_RESP_FIRST;
				hrr_fsmState = GENERATE;
			}
#if !POINTER_CHASING_EN
			memoryReadCmd.write(memCmdInternal(request.qpn, readAddr, dmaLength));
#else
			memoryReadCmd.write(memCmdInternal(request.qpn, readAddr, dmaLength, request.route));
#endif
			// event needs to contain QP, opCode, length, psn
			readEventFifo.write(event(readOpcode, request.qpn, readLength, request.psn));
		}
		break;
	case GENERATE:
		readAddr = request.vaddr;
		readLength = request.dma_length;
		if (request.dma_length > PMTU)
		{
			readLength = PMTU;
			request.vaddr += PMTU;
			request.dma_length -= PMTU;
			readOpcode = RC_RDMA_READ_RESP_MIDDLE;
		}
		else
		{
			readOpcode = RC_RDMA_READ_RESP_LAST;
			hrr_fsmState = META;
		}
		// memoryReadCmd.write(memCmdInternal(request.qpn, readAddr, readLength, (readOpcode == RC_RDMA_READ_RESP_LAST)));
		request.psn++;
		readEventFifo.write(event(readOpcode, request.qpn, readLength, request.psn));
		break;
	}
}
/*
 * For everything, except READ_RSP, we get PSN from state_table
 */
template <int WIDTH>
void generate_ibh(stream<ibhMeta> &metaIn,
				  stream<ap_uint<24>> &dstQpIn,
				  stream<stateTableEntry> &stateTable2txIbh_rsp,
				  // stream<net_axis<WIDTH> >&			input,
				  stream<txStateReq> &txIbh2stateTable_upd_req,
#if RETRANS_EN
				  stream<retransMeta> &tx2retrans_insertMeta,
#endif
				  stream<BaseTransportHeader<WIDTH>> &tx_ibhHeaderFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"generate_ibh 函数开始执行"<<std::endl;
	enum fsmStateType
	{
		META,
		GET_PSN
	};
	static fsmStateType gi_state = META;
	static BaseTransportHeader<WIDTH> header;

	static ibhMeta meta;
	net_axis<WIDTH> currWord;
	stateTableEntry qpState; // TODO what is really required
	ap_uint<24> dstQp;

	switch (gi_state)
	{
	case META:
		if (!metaIn.empty() && !dstQpIn.empty())
		{
			metaIn.read(meta);
			dstQpIn.read(dstQp);
			meta.partition_key = 0xFFFF; // TODO this is hard-coded, where does it come from??
			header.clear();

			header.setOpCode(meta.op_code);
			header.setPartitionKey(meta.partition_key);
			// PSN only valid for READ_RSP, otherwise we get it in state GET_PSN
			header.setPsn(meta.psn);
			header.setDstQP(dstQp); // TODO ist meta.dest_qp required??
			header.setCodedID(meta.coded_id);
			std::cout << "编码信息:" << header.getCodedID() << std::endl;
			if (meta.validPsn)
			{
				tx_ibhHeaderFifo.write(header);
				// gi_state = HEADER;
			}
			else
			{
				txIbh2stateTable_upd_req.write(txStateReq(meta.dest_qp)); // TODO this is actually our qp
				gi_state = GET_PSN;
			}
		}
		break;
	case GET_PSN:
		if (!stateTable2txIbh_rsp.empty())
		{
			stateTable2txIbh_rsp.read(qpState);
			if (meta.op_code == RC_ACK)
			{
				header.setPsn(qpState.resp_epsn - 1); // TODO -1 necessary??
			}
			else
			{
				header.setPsn(qpState.req_next_psn);
				header.setAckReq(true);
				// Update PSN
				ap_uint<24> nextPsn = qpState.req_next_psn + meta.numPkg;
				txIbh2stateTable_upd_req.write(txStateReq(meta.dest_qp, nextPsn));

				// Store Packet descirptor in retransmitter table
#if RETRANS_EN
				tx2retrans_insertMeta.write(retransMeta(meta.dest_qp, qpState.req_next_psn, meta.op_code));
#endif
			}
			tx_ibhHeaderFifo.write(header);
			gi_state = META;
		}
		break;
	}
}

/*
 * Types currently supported: DETH, RETH, AETH, ImmDt, IETH
 *
 * For reliable connections, page 246, 266, 269
 * RDM WRITE ONLY: RETH, PayLd
 * RDMA WRITE FIRST: RETH, PayLd
 * RDMA WRITE MIDDLE: PayLd
 * RDMA WRITE LAST: PayLd
 * RDMA READ REQUEST: RETH
 * RDMA READ RESPONSE ONLY: AETH, PayLd
 * RDMA READ RESPONSE FIRST: AETH, PayLd
 * RDMA READ RESPONSE MIDDLE: PayLd
 * RDMA READ RESPONSE LAST: AETH, PayLd
 * ACK: AETH
 */
template <int WIDTH>
void generate_exh(stream<event> &metaIn,
				  stream<bool> &isCodedFifo1,
#if POINTER_CHASING_EN
				  stream<ptrChaseMeta> &s_axis_tx_pcmeta,
#endif
				  stream<txMsnRsp> &msnTable2txExh_rsp,
				  stream<ap_uint<16>> &txExh2msnTable_req,
				  stream<txReadReqUpdate> &tx_readReqTable_upd,
				  stream<ap_uint<16>> &lengthFifo,
				  stream<txPacketInfo> &packetInfoFifo,
				  stream<bool> &isCodedFifo2,
#if RETRANS_EN
				  stream<ap_uint<24>> &txSetTimer_req,
// stream<retransAddrLen>&		tx2retrans_insertAddrLen,
#endif
				  stream<net_axis<WIDTH>> &output)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"generate_exh 函数开始执行"<<std::endl;
	enum ge_fsmStateType
	{
		META,
		GET_MSN,
		PROCESS
	};
	static ge_fsmStateType ge_state = META;
	static event meta;
	net_axis<WIDTH> sendWord;
	static RdmaExHeader<WIDTH> rdmaHeader;
	static AckExHeader<WIDTH> ackHeader;
#if POINTER_CHASING_EN
	static ptrChaseMeta pcMeta;
	static RdmaPointerChaseHeader<WIDTH> pointerChaseHeader;
#endif
	static bool metaWritten;
	static txMsnRsp msnMeta;
	static bool isCoded = false;
	ap_uint<16> udpLen;
	txPacketInfo info;

	switch (ge_state)
	{
	case META:
		if (!metaIn.empty())
		{
			if (!isCodedFifo1.empty())
			{
				isCodedFifo1.read(isCoded);
				std::cout << "编码？--" << isCoded << std::endl;
			}
			rdmaHeader.clear();
			ackHeader.clear();
#if POINTER_CHASING_EN
			pointerChaseHeader.clear();
#endif

			metaIn.read(meta);

			metaWritten = false;
			// if (meta.op_code == RC_RDMA_READ_RESP_ONLY || meta.op_code == RC_RDMA_READ_RESP_FIRST || meta.op_code == RC_RDMA_READ_RESP_MIDDLE || meta.op_code == RC_RDMA_READ_RESP_LAST || meta.op_code == RC_ACK)
			{
				txExh2msnTable_req.write(meta.qpn);
				std::cout << "meta--" << meta.qpn << std::endl;
				ge_state = GET_MSN;
			}
			// else
			{
				// Start Timer for RDMW_WRITE_* & RDMA_READ_REQUEST

				// txSetTimer_req.write(meta.qpn);
				// ge_state = PROCESS;
			}
#if RETRANS_EN
			// TODO PART HIST
			if (meta.op_code == RC_RDMA_WRITE_ONLY || meta.op_code == RC_RDMA_WRITE_FIRST || meta.op_code == RC_RDMA_WRITE_MIDDLE || meta.op_code == RC_RDMA_WRITE_LAST || meta.op_code == RC_RDMA_READ_REQUEST)
			{
				txSetTimer_req.write(meta.qpn);
			}
#endif
		}
		break;
	case GET_MSN:
		std::cout << "GET_MSN" << std::endl;
#if POINTER_CHASING_EN
		if (!msnTable2txExh_rsp.empty() && (meta.op_code != RC_RDMA_READ_POINTER_REQUEST || !s_axis_tx_pcmeta.empty()))
#else
		if (!msnTable2txExh_rsp.empty()) // && (meta.op_code != RC_RDMA_READ_POINTER_REQUEST || !s_axis_tx_pcmeta.empty()))
#endif
		{
			msnTable2txExh_rsp.read(msnMeta);
#if POINTER_CHASING_EN
			if (meta.op_code == RC_RDMA_READ_POINTER_REQUEST)
			{
				s_axis_tx_pcmeta.read(pcMeta);
			}
#endif
			ge_state = PROCESS;
		}
		break;
	case PROCESS:
	{
		sendWord.last = 0;
		switch (meta.op_code)
		{
		case RC_RDMA_WRITE_ONLY:
		case RC_RDMA_WRITE_FIRST:
		case RC_RDMA_PART_ONLY:
		case RC_RDMA_PART_FIRST:
		{
			std::cout << "RC_RDMA_WRITE_FIRST!!!!" << std::endl;
			// [BTH][RETH][PayLd]
			rdmaHeader.setVirtualAddress(meta.addr);
			std::cout << "虚拟地址设置完成" << meta.addr << std::endl;
			rdmaHeader.setLength(meta.length); // TODO Move up??
			rdmaHeader.setRemoteKey(msnMeta.r_key);
			std::cout << "r_key:" << rdmaHeader.getRemoteKey() << std::endl;
			ap_uint<8> remainingLength = rdmaHeader.consumeWord(sendWord.data);
			sendWord.keep = ~0;
			sendWord.last = (remainingLength == 0);
			std::cout << "RDMA_WRITE_ONLY/FIRST ";
			print(std::cout, sendWord);
			std::cout << std::endl;
			output.write(sendWord);
			if (remainingLength == 0)
			{
				// TODO
			}
			if (!metaWritten) // TODO we are losing 1 cycle here
			{
				info.isAETH = false;
				info.hasHeader = true;
				info.hasPayload = (meta.length != 0); // TODO should be true
				packetInfoFifo.write(info);
				std::cout << "是否编码?" << isCoded << std::endl;
				isCodedFifo2.write(isCoded);

				/*std::cout << "RDMA_WRITE_ONLY/FIRST ";
				print(std::cout, sendWord);
				std::cout << std::endl;
				output.write(sendWord);*/

				// BTH: 12, RETH: 16, PayLd: x, ICRC: 4
				ap_uint<32> payloadLen = meta.length;
				if ((meta.op_code == RC_RDMA_WRITE_FIRST) || (meta.op_code == RC_RDMA_PART_FIRST))
				{
					payloadLen = PMTU;
				}
				if (isCoded)
				{
					udpLen = 12 + 4 + 16 + payloadLen + 4;
				}
				else
				{
					udpLen = 12 + 16 + payloadLen + 4; // TODO dma_len can be much larger, for multiple packets we need to split this into multiple packets
				}
				lengthFifo.write(udpLen);
				// Store meta for retransmit
				/*#if RETRANS_EN
									if (!meta.validPsn) //indicates retransmission
									{
										tx2retrans_insertAddrLen.write(retransAddrLen(meta.addr, meta.length));
									}
				#endif*/
				metaWritten = true;
			}
			break;
		}
		case RC_RDMA_WRITE_MIDDLE:
		case RC_RDMA_WRITE_LAST:
		case RC_RDMA_PART_MIDDLE:
		case RC_RDMA_PART_LAST:
			// [BTH][PayLd]
			info.isAETH = false;
			info.hasHeader = false;
			info.hasPayload = (meta.length != 0); // TODO should be true
			packetInfoFifo.write(info);
			isCodedFifo2.write(isCoded);
			// BTH: 12, PayLd: x, ICRC: 4
			if (isCoded)
			{
				udpLen = 12 + 4 + meta.length + 4;
			}
			else
			{
				udpLen = 12 + meta.length + 4;
			}

			lengthFifo.write(udpLen);
			// Store meta for retransmit
			/*#if RETRANS_EN
							if (!meta.validPsn) //indicates retransmission
							{
								tx2retrans_insertAddrLen.write(retransAddrLen(meta.addr, meta.length));
							}
			#endif*/
			ge_state = META;
			break;
		case RC_RDMA_READ_REQUEST:
		case RC_RDMA_READ_CONSISTENT_REQUEST:
		{
			// [BTH][RETH]
			rdmaHeader.setVirtualAddress(meta.addr);
			rdmaHeader.setLength(meta.length); // TODO Move up??
			rdmaHeader.setRemoteKey(msnMeta.r_key);
			ap_uint<8> remainingLength = rdmaHeader.consumeWord(sendWord.data);
			sendWord.keep = ~0;
			sendWord.last = (remainingLength == 0);
			std::cout << "RDMA_READ_RWQ ";
			print(std::cout, sendWord);
			std::cout << std::endl;
			output.write(sendWord);
			if (!metaWritten) // TODO we are losing 1 cycle here
			{
				info.isAETH = false;
				info.hasHeader = true;
				info.hasPayload = false; //(meta.length != 0); //TODO should be true
				packetInfoFifo.write(info);
				isCodedFifo2.write(isCoded);

				/*std::cout << "RDMA_READ_RWQ ";
				print(std::cout, sendWord);
				std::cout << std::endl;
				output.write(sendWord);*/

				// BTH: 12, RETH: 16, PayLd: x, ICRC: 4
				udpLen = 12 + 16 + 0 + 4; // TODO dma_len can be much larger, for multiple packets we need to split this into multiple packets
				lengthFifo.write(udpLen);
				// Update Read Req max FWD header, TODO it is not exacly clear if meta.psn or meta.psn+numPkgs should be used
				// TODO i think psn is only used here!!
				tx_readReqTable_upd.write(txReadReqUpdate(meta.qpn, meta.psn));
				// Store meta for retransmit
				/*#if RETRANS_EN
									if (!meta.validPsn) //indicates retransmission
									{
										tx2retrans_insertAddrLen.write(retransAddrLen(meta.addr, meta.length));
									}
				#endif*/
				metaWritten = true;
			}
			break;
		}
#if POINTER_CHASING_EN
		case RC_RDMA_READ_POINTER_REQUEST:
		{
			// [BTH][RCTH]
			pointerChaseHeader.setVirtualAddress(meta.addr);
			pointerChaseHeader.setLength(meta.length); // TODO Move up??
			pointerChaseHeader.setRemoteKey(msnMeta.r_key);
			pointerChaseHeader.setPredicateKey(pcMeta.key);
			pointerChaseHeader.setPredicateMask(pcMeta.mask);
			pointerChaseHeader.setPredicateOp(pcMeta.op);
			pointerChaseHeader.setPtrOffset(pcMeta.ptrOffset);
			pointerChaseHeader.setIsRelPtr(pcMeta.relPtrOffset);
			pointerChaseHeader.setNextPtrOffset(pcMeta.nextPtrOffset);
			pointerChaseHeader.setNexPtrValid(pcMeta.nextPtrValid);

			ap_uint<8> remainingLength = pointerChaseHeader.consumeWord(sendWord.data);
			sendWord.keep = ~0; // 0xFFFFFFFF; //TODO, set as much as required
			sendWord.last = (remainingLength == 0);
			std::cout << "RC_RDMA_READ_POINTER_REQUEST ";
			print(std::cout, sendWord);
			std::cout << std::endl;
			output.write(sendWord);
			if (!metaWritten) // TODO we are losing 1 cycle here
			{
				info.isAETH = false; // TODO fix this
				info.hasHeader = true;
				info.hasPayload = false; //(meta.length != 0); //TODO should be true
				packetInfoFifo.write(info);

				/*std::cout << "RC_RDMA_READ_POINTER_REQUEST ";
				print(std::cout, sendWord);
				std::cout << std::endl;
				output.write(sendWord);*/

				// BTH: 12, RCTH: 28, PayLd: x, ICRC: 4
				udpLen = 12 + 28 + 0 + 4;
				lengthFifo.write(udpLen);
				// Update Read Req max FWD header, TODO it is not exacly clear if meta.psn or meta.psn+numPkgs should be used
				// TODO i think psn is only used here!!
				tx_readReqTable_upd.write(txReadReqUpdate(meta.qpn, meta.psn));
				// Store meta for retransmit
				/*#if RETRANS_EN
									if (!meta.validPsn) //indicates retransmission
									{
										tx2retrans_insertAddrLen.write(retransAddrLen(meta.addr, meta.length));
									}
				#endif*/
				metaWritten = true;
			}
			break;
		}
#endif
		case RC_RDMA_READ_RESP_ONLY:
		case RC_RDMA_READ_RESP_FIRST:
		case RC_RDMA_READ_RESP_LAST:
		{
			// [BTH][AETH][PayLd]
			// AETH for first and last
			ackHeader.setSyndrome(0x1f);
			ackHeader.setMsn(msnMeta.msn);
			std::cout << "RDMA_READ_RESP MSN:" << ackHeader.getMsn() << std::endl;
			ackHeader.consumeWord(sendWord.data); // TODO
			{
				info.isAETH = true;
				info.hasHeader = true;
				info.hasPayload = (meta.length != 0); // TODO should be true
				packetInfoFifo.write(info);
				isCodedFifo2.write(isCoded);

				sendWord.keep((AETH_SIZE / 8) - 1, 0) = 0xFF;
				sendWord.keep((WIDTH / 8) - 1, (AETH_SIZE / 8)) = 0;
				sendWord.last = 1;

				std::cout << "RDMA_READ_RESP ";
				print(std::cout, sendWord);
				std::cout << std::endl;
				output.write(sendWord);

				// BTH: 12, AETH: 4, PayLd: x, ICRC: 4
				if (isCoded)
				{
					udpLen = 12 + 4 + 4 + meta.length + 4;
				}
				else
				{
					udpLen = 12 + 4 + meta.length + 4;
				}

				// std::cout << "length: " << tempLen << ", dma len: " << meta.length << std::endl;
				lengthFifo.write(udpLen);
			}
			break;
		}
		case RC_RDMA_READ_RESP_MIDDLE:
			// [BTH][PayLd]
			info.isAETH = true;
			info.hasHeader = false;
			info.hasPayload = (meta.length != 0); // TODO should be true
			packetInfoFifo.write(info);
			isCodedFifo2.write(isCoded);
			// BTH: 12, PayLd: x, ICRC: 4
			if (isCoded)
			{
				udpLen = 12 + 4 + meta.length + 4;
			}
			else
			{
				udpLen = 12 + meta.length + 4;
			}
			lengthFifo.write(udpLen);
			ge_state = META;
			break;
		case RC_ACK:
		{
			// [BTH][AETH]
			// Check if ACK or NAK
			if (!meta.isNak)
			{
				ackHeader.setSyndrome(0x1f);
			}
			else
			{
				// PSN SEQ error
				ackHeader.setSyndrome(0x60);
			}
			ackHeader.setMsn(msnMeta.msn);
			std::cout << "RC_ACK MSN:" << ackHeader.getMsn() << std::endl;
			ackHeader.consumeWord(sendWord.data); // TODO
			{
				info.isAETH = true;
				info.hasHeader = true;
				info.hasPayload = false;
				packetInfoFifo.write(info);
				isCodedFifo2.write(isCoded);

				sendWord.keep(AETH_SIZE / 8 - 1, 0) = 0xFF;
				sendWord.keep((WIDTH / 8) - 1, (AETH_SIZE / 8)) = 0;
				sendWord.last = 1;

				std::cout << "RC_ACK ";
				print(std::cout, sendWord);
				std::cout << std::endl;
				output.write(sendWord);

				// BTH: 12, AETH: 4, ICRC: 4
				lengthFifo.write(12 + 4 + 4);
			}
			break;
		}
		default:
			break;
		} // switch
	} // if empty
		if (sendWord.last)
		{
			ge_state = META;
		}
		break;
	} // switch
}

template <int WIDTH>
void append_payload(stream<txPacketInfo> &packetInfoFifo,
					stream<bool> &tx_isCodedFifo,
					stream<bool> &tx_isCodedFifo3,
					stream<net_axis<WIDTH>> &tx_headerFifo,
					stream<net_axis<WIDTH>> &tx_aethPayloadFifo,
					stream<net_axis<WIDTH>> &tx_rethPayloadFifo,
					stream<net_axis<WIDTH>> &tx_rawPayloadFifo,
					stream<net_axis<WIDTH>> &tx_codedPacketFifo,
					stream<net_axis<WIDTH>> &tx_packetFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"append_payload 函数开始执行"<<std::endl;
	enum fsmState
	{
		INFO,
		HEADER,
		AETH_PAYLOAD,
		RETH_PAYLOAD,
		RAW_PAYLOAD
	};
	static fsmState state = INFO;
	static net_axis<WIDTH> prevWord;
	net_axis<WIDTH> currWord;
	net_axis<WIDTH> sendWord;
	static bool firstPayload = true;

	static txPacketInfo info;
	static bool isCoded = false;

	// TODO align this stuff!!
	switch (state)
	{
	case INFO:
		if (!packetInfoFifo.empty())
		{
			if (!tx_isCodedFifo.empty())
			{
				tx_isCodedFifo.read(isCoded);
				tx_isCodedFifo3.write(isCoded);
			}
			firstPayload = true;
			packetInfoFifo.read(info);

			if (info.hasHeader)
			{
				state = HEADER;
			}
			else
			{
				state = RAW_PAYLOAD;
			}
		}
		break;
	case HEADER:
		if (!tx_headerFifo.empty())
		{
			tx_headerFifo.read(prevWord);
			/*std::cout << "HEADER:";
			print(std::cout, prevWord);
			std::cout << std::endl;*/
			// TODO last is not necessary
			if (!prevWord.last) // || prevWord.keep[(WIDTH/8)-1] == 1) //One of them should be sufficient..
			{
				if (isCoded)
				{
					tx_codedPacketFifo.write(prevWord);
				}
				else
				{
					tx_packetFifo.write(prevWord);
				}
			}
			else // last
			{
				if (!info.hasPayload)
				{
					state = INFO;
					if (isCoded)
					{
						tx_codedPacketFifo.write(prevWord);
					}
					else
					{
						tx_packetFifo.write(prevWord);
					}
				}
				else // hasPayload
				{
					prevWord.last = 0;
					if (info.isAETH)
					{
						state = AETH_PAYLOAD;
					}
					else // RETH
					{
						if (WIDTH <= RETH_SIZE)
						{
							if (isCoded)
							{
								tx_codedPacketFifo.write(prevWord);
							}
							else
							{
								tx_packetFifo.write(prevWord);
							}
						}
						state = RETH_PAYLOAD;
					}
				}
			}
		}
		break;
	case AETH_PAYLOAD:
		if (!tx_aethPayloadFifo.empty())
		{
			tx_aethPayloadFifo.read(currWord);
			std::cout << "PAYLOAD WORD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			sendWord = currWord;
			if (firstPayload)
			{
				sendWord.data(31, 0) = prevWord.data(31, 0);
				firstPayload = false;
			}
			std::cout << "AETH PAY: ";
			print(std::cout, sendWord);
			std::cout << std::endl;
			if (isCoded)
			{
				tx_codedPacketFifo.write(sendWord);
			}
			else
			{
				tx_packetFifo.write(sendWord);
			}
			if (currWord.last)
			{
				state = INFO;
			}
		}
		break;
	case RETH_PAYLOAD:
		if (!tx_rethPayloadFifo.empty())
		{
			tx_rethPayloadFifo.read(currWord);
			std::cout << "PAYLOAD WORD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			sendWord = currWord;
			if (firstPayload && WIDTH > RETH_SIZE)
			{
				sendWord.data(127, 0) = prevWord.data(127, 0);
				firstPayload = false;
			}

			std::cout << "RETH PAYLOAD: ";
			print(std::cout, sendWord);
			std::cout << std::endl;

			if (isCoded)
			{
				tx_codedPacketFifo.write(sendWord);
			}
			else
			{
				tx_packetFifo.write(sendWord);
			}
			if (currWord.last)
			{
				state = INFO;
			}
		}
		break;
	case RAW_PAYLOAD:
		if (!tx_rawPayloadFifo.empty())
		{
			tx_rawPayloadFifo.read(currWord);
			if (isCoded)
			{
				tx_codedPacketFifo.write(currWord);
			}
			else
			{
				tx_packetFifo.write(currWord);
			}
			if (currWord.last)
			{
				state = INFO;
			}
		}
		break;
	}
}

// TODO this introduces 1 cycle for WIDTH > 64
template <int WIDTH>
void prepend_ibh_header(stream<BaseTransportHeader<WIDTH>> &tx_ibhHeaderFifo,
						stream<bool> &tx_isCodedFifo3,
						stream<net_axis<WIDTH>> &tx_ibhPayloadFifo,
						stream<net_axis<WIDTH>> &tx_ibhCodedPayloadFifo,
						stream<net_axis<WIDTH>> &m_axis_tx_data,
						ap_uint<64> &rawTime,
						ap_uint<64> &totalTime,
						ap_uint<64> &currCycle)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"prepend_ibh_header 函数开始执行"<<std::endl;
	enum pihStatea
	{
		GET_HEADER,
		HEADER,
		PARTIAL_HEADER,
		BODY,
		CODE_PARTIAL_HEADER,
		CODE_BODY
	};
	static pihStatea state = GET_HEADER;
	static BaseTransportHeader<WIDTH> header;
	static ap_uint<WIDTH> headerData;
	static bool isCoded = false;
	net_axis<WIDTH> currWord;
	switch (state)
	{
	case GET_HEADER:
		if (!tx_ibhHeaderFifo.empty())
		{
			if (!tx_isCodedFifo3.empty())
			{
				tx_isCodedFifo3.read(isCoded);
			}
			tx_ibhHeaderFifo.read(header);
			if (BTH_SIZE >= WIDTH)
			{
				state = HEADER;
			}
			else
			{
				if (isCoded)
				{
					state = CODE_PARTIAL_HEADER;
				}
				else
				{
					state = PARTIAL_HEADER;
				}
			}
		}
		break;
	case HEADER:
	{
		ap_uint<8> remainingLength = header.consumeWord(currWord.data);
		if (remainingLength < (WIDTH / 8))
		{
			if (isCoded)
			{
				state = CODE_PARTIAL_HEADER;
			}
			else
			{
				state = PARTIAL_HEADER;
			}
		}
		currWord.keep = ~0;
		currWord.last = 0;
		m_axis_tx_data.write(currWord);
		totalTime = currCycle;
		if (!header.getCodedID()[2])
		{
			rawTime = currCycle;
		}

		std::cout << "IBH HEADER: ";
		print(std::cout, currWord);
		std::cout << std::endl;
		break;
	}
	case PARTIAL_HEADER:
		if (!tx_ibhPayloadFifo.empty())
		{
			tx_ibhPayloadFifo.read(currWord);
			std::cout << "IBH PARTIAL PAYLOAD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			header.consumeWord(currWord.data);
			m_axis_tx_data.write(currWord);
			totalTime = currCycle;

			if (!header.getCodedID()[2])
			{
				rawTime = currCycle;
			}

			std::cout << "IBH PARTIAL HEADER: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			state = BODY;
			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	case CODE_PARTIAL_HEADER:
		if (!tx_ibhCodedPayloadFifo.empty())
		{
			tx_ibhCodedPayloadFifo.read(currWord);
			std::cout << "IBH PARTIAL PAYLOAD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			header.consumeWord(currWord.data);
			m_axis_tx_data.write(currWord);
			totalTime = currCycle;

			if (!header.getCodedID()[2])
			{
				rawTime = currCycle;
			}

			std::cout << "IBH PARTIAL HEADER: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			state = CODE_BODY;
			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	case BODY:
		if (!tx_ibhPayloadFifo.empty())
		{
			tx_ibhPayloadFifo.read(currWord);
			m_axis_tx_data.write(currWord);
			totalTime = currCycle;

			if (!header.getCodedID()[2])
			{
				rawTime = currCycle;
			}

			std::cout << "IBH PAYLOAD WORD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	case CODE_BODY:
		if (!tx_ibhCodedPayloadFifo.empty())
		{
			tx_ibhCodedPayloadFifo.read(currWord);
			m_axis_tx_data.write(currWord);
			totalTime = currCycle;

			if (!header.getCodedID()[2])
			{
				rawTime = currCycle;
			}

			std::cout << "IBH PAYLOAD WORD: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	}
}
template <int WIDTH>
void prepend_ceth_header(stream<codedExh> &tx_codedExhFifo,
						 stream<net_axis<WIDTH>> &tx_codedshiftFifo,
						 stream<net_axis<WIDTH>> &tx_codedcethshiftFifo)
{
	enum cethstate
	{
		GET_HEADER,
		HEADER,
		BODY
	};
	static cethstate state = GET_HEADER;
	CodeExHeader<WIDTH> codeExHeader;
	static codedExh coded;
	net_axis<WIDTH> currWord;
	switch (state)
	{
	case GET_HEADER:
		if (!tx_codedExhFifo.empty())
		{

			tx_codedExhFifo.read(coded);
			std::cout << "获取CETH:批次:" << coded.codeBat << "初始包:" << coded.oriNum << "恢复包:" << coded.repNum << std::endl;
			state = HEADER;
		}
		break;
	case HEADER:
		if (!tx_codedshiftFifo.empty())
		{
			codeExHeader.setCodeBat(coded.codeBat);
			codeExHeader.setOriNum(coded.oriNum);
			codeExHeader.setRepNum(coded.repNum);
			tx_codedshiftFifo.read(currWord);
			std::cout << "追加CETH之前:";
			print(std::cout, currWord);
			std::cout << std::endl;
			std::cout << "当前编码头信息:" << codeExHeader.getCodeBat() << "初始包:" << codeExHeader.getOriNum() << "恢复包:" << codeExHeader.getRepNum() << std::endl;
			codeExHeader.consumeWord(currWord.data);
			tx_codedcethshiftFifo.write(currWord);
			std::cout << "追加CETH:";
			print(std::cout, currWord);
			std::cout << std::endl;
			state = BODY;
			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	case BODY:
		if (!tx_codedshiftFifo.empty())
		{
			tx_codedshiftFifo.read(currWord);

			tx_codedcethshiftFifo.write(currWord);
			std::cout << "追加CETH--BODY:";
			print(std::cout, currWord);
			std::cout << std::endl;
			if (currWord.last)
			{
				state = GET_HEADER;
			}
		}
		break;
	}
}

/*
这段代码实现了一个有限状态机函数 local_req_handler，用于处理本地请求，它根据接收到的元数据生成读、写请求并与重传模块进行交互。它主要处理的是从发送请求到生成内存访问命令和元数据（事件）转发的流程。

具体来说，这个函数有以下主要功能：

处理来自应用的写和读请求。
根据是否启用重传（通过 RETRANS_EN 宏来控制）来处理重传相关的元数据。
根据数据包长度，生成必要的传输事件和内存读写命令。
实现 RDMA 操作，包括写操作拆分成多个段（FIRST，MIDDLE，LAST）的流程。
主要输入参数
s_axis_tx_meta：包含应用程序产生的发送请求元数据，用于指示 RDMA 操作。
retransEventFifo（在启用重传时）：用于存储重传事件。
tx_local_memCmdFifo：输出的内存命令流，用于生成内存写入操作。
tx_localReadAddrFifo：输出的本地读取地址流，用于记录读取操作的本地地址。
tx_localTxMeta：生成的 RDMA 操作的元数据。
tx2retrans_insertAddrLen（在启用重传时）：用于传输重传地址和长度信息。
状态机解析
这个函数基于两种状态实现有限状态机：

META：处理来自应用或者重传事件的元数据，决定是否生成写入命令、读取命令或其他相关的内存操作。
GENERATE：当写操作的数据量超过 PMTU 时，生成相应的写请求，将请求拆分为多个小块，直到处理完成。
代码逻辑解析
1. 定义的变量和类型
fsmStateType：定义状态机的状态，可能是 META 或 GENERATE。
meta：存储从 s_axis_tx_meta 中读取的元数据，用于处理请求。
event 和 retransEvent：生成的事件，用于描述需要执行的 RDMA 操作。
ibOpCode：RDMA 操作码，例如读、写等操作类型。
raddr 和 laddr：分别为远程和本地地址。
length 和 dmaLength：表示要进行读写操作的数据长度。

*/
void local_req_handler(stream<txMeta> &s_axis_tx_meta,
#if RETRANS_EN
					   stream<retransEvent> &retransEventFifo,
#endif
					   stream<memCmdInternal> &tx_local_memCmdFifo, // TODO rename
					   gf256 &gf,
					   stream<mqInsertReq<ap_uint<64>>> &tx_localReadAddrFifo,
					   stream<codeInfo> &code_info_Fifo,
					   stream<codeJudge> &code_judge_Fifo,
#if !RETRANS_EN
					   stream<event> &tx_localTxMeta)
#else
					   stream<event> &tx_localTxMeta,
					   stream<retransAddrLen> &tx2retrans_insertAddrLen)
#endif
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"local_req_handler 函数开始执行"<<std::endl;
	enum fsmStateType
	{
		META,
		GENERATE
	};
	static fsmStateType lrh_state;
	static txMeta meta;
	static ap_uint<8> row = 0;
	static ap_uint<16> codeBat = 0;

	event ev;
	retransEvent rev;
	codeInfo codeinfo;
	codeJudge codejudge;
	ibOpCode writeOpcode;
	ap_uint<48> raddr;
	ap_uint<48> laddr;
	ap_uint<32> length;
	ap_uint<32> dmaLength;
	ap_uint<4> coded_id;
	bool validCODE = false;
	bool newBat = false;
	bool iscode = true;

	switch (lrh_state)
	{
	case META:
#if RETRANS_EN
		if (!retransEventFifo.empty())
		{
			retransEventFifo.read(rev);
			tx_localTxMeta.write(event(rev.op_code, rev.qpn, rev.remoteAddr, rev.length, rev.psn));
			if (rev.op_code != RC_RDMA_READ_REQUEST)
			{
				length = rev.length;
				std::cout << std::dec << "length to retranmist: " << rev.length << ", local addr: " << std::hex << rev.localAddr << ", remote addres: " << rev.remoteAddr << ", psn: " << rev.psn << std::endl;
				if (ev.op_code == RC_RDMA_WRITE_FIRST || ev.op_code == RC_RDMA_PART_FIRST)
				{
					length = PMTU;
				}
				tx_local_memCmdFifo.write(memCmdInternal(rev.qpn, rev.localAddr, length));
			}
		}
		else if (!s_axis_tx_meta.empty())
#else
		if (!s_axis_tx_meta.empty())
#endif
		{
			s_axis_tx_meta.read(meta);
			if (meta.op_code == APP_READ || meta.op_code == APP_POINTER || meta.op_code == APP_READ_CONSISTENT)
			{
				if (meta.op_code == APP_READ)
				{
					tx_localTxMeta.write(event(RC_RDMA_READ_REQUEST, meta.qpn, meta.remote_vaddr, meta.length));
				}
				else if (meta.op_code == APP_READ_CONSISTENT)
				{
					tx_localTxMeta.write(event(RC_RDMA_READ_CONSISTENT_REQUEST, meta.qpn, meta.remote_vaddr, meta.length));
				}
#if POINTER_CHASING_EN
				else
				{
					tx_localTxMeta.write(event(RC_RDMA_READ_POINTER_REQUEST, meta.qpn, meta.remote_vaddr, meta.length));
				}
#endif
				tx_localReadAddrFifo.write(mqInsertReq<ap_uint<64>>(meta.qpn, meta.local_vaddr));
#if RETRANS_EN
				tx2retrans_insertAddrLen.write(retransAddrLen(meta.local_vaddr, meta.remote_vaddr, meta.length));
#endif
			}
			else // APP_WRITE, APP_PART
			{
				laddr = meta.local_vaddr;
				raddr = meta.remote_vaddr;
				dmaLength = meta.length;
				writeOpcode = (meta.op_code == APP_PART) ? RC_RDMA_PART_ONLY : RC_RDMA_WRITE_ONLY;

				if (meta.length > PMTU)
				{
					meta.local_vaddr += PMTU;
					meta.remote_vaddr += PMTU;
					meta.length -= PMTU;
					writeOpcode = (meta.op_code == APP_PART) ? RC_RDMA_PART_FIRST : RC_RDMA_WRITE_FIRST;
					lrh_state = GENERATE;
				}
				// TODO retintroduce this functionality
				/*if (dmaLength > PCIE_BATCH_SIZE)
				{
					dmaLength -= PCIE_BATCH_SIZE;
					tx_local_memCmdFifo.write(memCmdInternal(meta.qpn, laddr, PCIE_BATCH_SIZE));
				}
				else*/
				{
					tx_local_memCmdFifo.write(memCmdInternal(meta.qpn, laddr, dmaLength));
				}
				if (iscode)
				{

					gf.initialize();
					codejudge.needCode = true;
					codeinfo.op_code = writeOpcode;
					codeinfo.initPkgAll = (dmaLength + PMTU - 1) / PMTU;
					codeinfo.codeBat = codeBat;
					codeinfo.qpn = meta.qpn;
					codeinfo.length = dmaLength;
					std::cout << "codeinfo信息写入:qpn:" << codeinfo.qpn << std::endl;
					std::cout << "原始包数量：" << codeinfo.initPkgAll << std::endl;
					codeinfo.repairPkgAll = codeinfo.initPkgAll * CODE_RATIO + 1;
					std::cout << "恢复包数量：" << codeinfo.repairPkgAll << std::endl;
					codeinfo.addr = raddr;
					code_info_Fifo.write(codeinfo);
					codejudge.first = true;
					row++;
					codejudge.row = row;
					coded_id[3] = 1;
					coded_id[2] = 0;
					coded_id[1] = 1;
					if (meta.length > PMTU)
					{
						coded_id[0] = 0;
						codejudge.tail = false;
					}
					else
					{
						coded_id[0] = 1;
						codejudge.tail = true;
					}
					validCODE = true;
				}
				else
				{
					codejudge.needCode = false;
				}
				tx_localTxMeta.write(event(writeOpcode, meta.qpn, raddr, dmaLength, validCODE, coded_id));
				code_judge_Fifo.write(codejudge);
#if RETRANS_EN
				tx2retrans_insertAddrLen.write(retransAddrLen(laddr, raddr, dmaLength));
#endif
			}
		}
		break;
	case GENERATE:
		laddr = meta.local_vaddr;
		raddr = meta.remote_vaddr;
		length = meta.length;
		std::cout << "后续数据包剩余:" << (length + PMTU - 1) / PMTU << std::endl;
		if (meta.length > PMTU)
		{
			length = PMTU;
			meta.local_vaddr += PMTU;
			meta.remote_vaddr += PMTU;
			meta.length -= PMTU;
			writeOpcode = (meta.op_code == APP_PART) ? RC_RDMA_PART_MIDDLE : RC_RDMA_WRITE_MIDDLE;
		}
		else
		{
			writeOpcode = (meta.op_code == APP_PART) ? RC_RDMA_PART_LAST : RC_RDMA_WRITE_LAST;
			lrh_state = META;
		}
		if (iscode)
		{
			if (newBat)
			{
				codeBat++;
				row = 0;
			}
			codejudge.needCode = true;
			row++;
			codejudge.row = row;
			validCODE = true;
			coded_id[3] = 1;
			coded_id[2] = 0;
			coded_id[1] = 0;
			if (meta.length > PMTU)
			{
				coded_id[0] = 0;
			}
			else
			{
				coded_id[0] = 1;
			}
		}
		else
		{
			codejudge.needCode = false;
		}
		if (iscode && row == 0)
		{
			gf.initialize();
			codeinfo.op_code = writeOpcode;
			codeinfo.codeBat = codeBat;
			codeinfo.qpn = meta.qpn;
			codeinfo.length = dmaLength;
			codeinfo.initPkgAll = (dmaLength + PMTU - 1) / PMTU;
			std::cout << "原始包数量：" << codeinfo.initPkgAll << std::endl;
			codeinfo.repairPkgAll = codeinfo.initPkgAll * CODE_RATIO + 1;
			std::cout << "恢复包数量：" << codeinfo.repairPkgAll << std::endl;
			codeinfo.addr = raddr;
			code_info_Fifo.write(codeinfo);
		}
		code_judge_Fifo.write(codejudge);
		// tx_local_memCmdFifo.write(memCmdInternal(meta.qpn, laddr, length, (writeOpcode == RC_RDMA_WRITE_LAST || writeOpcode == RC_RDMA_PART_LAST)));//之前这行是注释了的
		tx_local_memCmdFifo.write(memCmdInternal(meta.qpn, laddr, length));
		tx_localTxMeta.write(event(writeOpcode, meta.qpn, raddr, length, validCODE, coded_id));
#if RETRANS_EN
		tx2retrans_insertAddrLen.write(retransAddrLen(laddr, raddr, length));
#endif
		break;
	} // switch
}

// TODO this only works with axi width 64
template <int WIDTH>
void fpga_data_handler(stream<net_axis<WIDTH>> &s_axis_tx_data,
					   stream<net_axis<WIDTH>> &appTxData) // switch to internal format
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"fpga_data_handler 函数开始执行"<<std::endl;
	static ap_uint<16> remainingLength;

	net_axis<WIDTH> currWord;

	if (!s_axis_tx_data.empty())
	{
		s_axis_tx_data.read(currWord);
		remainingLength -= (WIDTH / 8); // TODO only works with WIDTH == 64
		if (remainingLength == 0)
		{
			currWord.last = 1;
			remainingLength = PMTU;
		}
		appTxData.write(currWord);
	}
}

/*
 * rx_ackEventFifo RC_ACK from ibh and exh
 * rx_readEvenFifo READ events from RX side
 * tx_appMetaFifo, retransmission events, WRITEs and READ_REQ only
 */
void meta_merger(stream<ackEvent> &rx_ackEventFifo,
				 stream<event> &rx_readEvenFifo,
				 stream<event> &tx_appMetaFifo,
				 stream<codedIB> &tx_codedIBFifo,
				 // stream<event>&		timer2exhFifo,
				 stream<ap_uint<16>> &tx_connTable_req,
				 stream<ibhMeta> &tx_ibhMetaFifo,
				 stream<event> &tx_exhMetaFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"meta_merger 函数开始执行"<<std::endl;
	ackEvent aev;
	event ev;
	codedIB ci;
	ap_uint<16> key = 0; // TODO hack

	if (!rx_ackEventFifo.empty())
	{
		rx_ackEventFifo.read(aev);

		tx_connTable_req.write(aev.qpn(15, 0));
		// PSN used for read response
		tx_ibhMetaFifo.write(ibhMeta(RC_ACK, key, aev.qpn, aev.psn, aev.validPsn));
		tx_exhMetaFifo.write(event(aev));
	}
	else if (!rx_readEvenFifo.empty())
	{
		rx_readEvenFifo.read(ev);
		tx_connTable_req.write(ev.qpn(15, 0));
		// PSN used for read response
		tx_ibhMetaFifo.write(ibhMeta(ev.op_code, key, ev.qpn, ev.psn, ev.validPsn));
		tx_exhMetaFifo.write(ev);
	}
	else if (!tx_codedIBFifo.empty())
	{
		tx_codedIBFifo.read(ci);
		ap_uint<22> numPkg = 1;
		tx_connTable_req.write(ci.qpn(15, 0));
		if (ev.validPsn) // retransmit
		{
			tx_ibhMetaFifo.write(ibhMeta(ci.op_code, key, ci.qpn, ci.psn, ci.validPSN));
		}
		else // local
		{
			tx_ibhMetaFifo.write(ibhMeta(ci.op_code, key, ci.qpn, ci.codedId));
			std::cout << "恢复包编码信息已填充:" << ci.codedId << "操作码:" << ci.op_code << std::endl;
		}
		tx_exhMetaFifo.write(event(ci.op_code, ci.qpn, ci.addr, ci.length));
		std::cout << "扩展头信息:" << ci.op_code << "qpn:" << ci.qpn << "addr:" << ci.addr << "length:" << ci.length << std::endl;
	}
	else if (!tx_appMetaFifo.empty()) // TODO rename
	{
		tx_appMetaFifo.read(ev);

		ap_uint<22> numPkg = 1;
		if (ev.op_code == RC_RDMA_READ_REQUEST || ev.op_code == RC_RDMA_READ_POINTER_REQUEST || ev.op_code == RC_RDMA_READ_CONSISTENT_REQUEST)
		{
			numPkg = (ev.length + (PMTU - 1)) / PMTU;
		}

		tx_connTable_req.write(ev.qpn(15, 0));
		if (ev.validPsn) // retransmit
		{
			tx_ibhMetaFifo.write(ibhMeta(ev.op_code, key, ev.qpn, ev.psn, ev.validPsn));
		}
		else // local
		{
			if (ev.validCODE)
			{
				tx_ibhMetaFifo.write(ibhMeta(ev.op_code, key, ev.qpn, numPkg, ev.coded_id));
				std::cout << "原始包编码信息已填充:" << ev.coded_id << "qpn:" << ev.qpn << std::endl;
			}
			else
			{
				tx_ibhMetaFifo.write(ibhMeta(ev.op_code, key, ev.qpn, numPkg));
			}
		}
		std::cout << "原始包扩展信息已填充:" << ev.op_code << "qpn:" << ev.qpn << std::endl;
		tx_exhMetaFifo.write(ev);
	}
	/*else if (!timer2exhFifo.empty())
	{
		timer2exhFifo.read(ev);

		tx_connTable_req.write(ev.qpn(15, 0));
		// PSN used for retransmission
		tx_ibhMetaFifo.write(ibhMeta(ev.op_code, key, ev.qpn, ev.psn, ev.validPsn));
		tx_exhMetaFifo.write(ev);
	}*/
}

// TODO maybe all ACKS should be triggered by ibhFSM?? what is the guarantee we should/have to give
// TODO this should become a BRAM, storage type of thing
/*

这段代码的功能是处理来自 IP 和 UDP 协议层的元数据 (ipUdpMeta)，并与扩展头部 (ExHeader<WIDTH>) 结合，生成相关信息用于后续处理。这种处理主要是为了在 RDMA 数据包通过不同层时保留和处理其元数据，从而确保后续的处理步骤能正确地获取和使用这些信息。

功能概述
输入流：
ipUdpMeta：存储 IP 和 UDP 层的元数据，主要包括源 IP 地址、目标 IP 地址、端口号、数据长度等。
ExHeader<WIDTH>：RDMA 扩展头部信息，主要用于存储 RDMA 协议中与数据传输相关的控制字段（如 RDMA 操作码、目标 QP、PSN 等）。
fwdPolicy：指示是否丢弃当前数据包，以及是否只需要发送 ACK 确认（ackOnly）。
输出流：
exh_lengthFifo：记录了元数据中的数据长度，这个长度信息将用于后续的扩展头部处理。
exHeaderOutput：将处理过的扩展头部输出，以便后续的数据处理步骤使用。
*/
template <int WIDTH>
void ipUdpMetaHandler(stream<ipUdpMeta> &input,
					  stream<ExHeader<WIDTH>> &exHeaderInput,
					  stream<fwdPolicy> &dropMetaIn,
					  // stream<dstTuple>&		output,
					  // stream<ap_uint<16> >&	remcrc_lengthFifo,
					  stream<ap_uint<16>> &exh_lengthFifo,
					  stream<ExHeader<WIDTH>> &exHeaderOutput)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"ipUdpMetaHandler 函数开始执行"<<std::endl;
	ipUdpMeta meta;
	ExHeader<WIDTH> header;
	fwdPolicy policy;
	bool isDrop;

	if (!input.empty() && !exHeaderInput.empty() && !dropMetaIn.empty())
	{
		input.read(meta);
		exHeaderInput.read(header);
		dropMetaIn.read(policy);
		if (!policy.isDrop) // TODO clean this up
		{
			if (!policy.ackOnly)
			{
				// remcrc_lengthFifo.write(meta.length - (8 + 12 + 4)); //UDP + BTH + CRC
				exh_lengthFifo.write(meta.length);
				exHeaderOutput.write(header);
			}
			// output.write(dstTuple(meta.their_address, meta.their_port));
		}
	}
}

void tx_ipUdpMetaMerger(stream<connTableEntry> &tx_connTable2ibh_rsp,
						stream<ap_uint<16>> &tx_lengthFifo,
						stream<ipUdpMeta> &m_axis_tx_meta,
						stream<ap_uint<24>> &tx_dstQpFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"tx_ipUdpMetaMerger 函数开始执行"<<std::endl;
	connTableEntry connMeta;
	ap_uint<16> len;

	if (!tx_connTable2ibh_rsp.empty() && !tx_lengthFifo.empty())
	{
		tx_connTable2ibh_rsp.read(connMeta);
		tx_lengthFifo.read(len);
		std::cout << "Remote PORT: " << connMeta.remote_udp_port << std::endl;
		m_axis_tx_meta.write(ipUdpMeta(connMeta.remote_ip_address, connMeta.remote_udp_port, RDMA_DEFAULT_PORT, len));
		tx_dstQpFifo.write(connMeta.remote_qpn);
	}
}

void qp_interface(stream<qpContext> &contextIn, // 传入的上下文信息
				  stream<stateTableEntry> &stateTable2qpi_rsp,
				  stream<ifStateReq> &qpi2stateTable_upd_req,
				  stream<ifMsnReq> &if2msnTable_init)
/*
contextIn (stream<qpContext>&)：输入流，包含新的 QP 上下文信息。这个流可以视为上层模块给定的 QP 的初始化或状态变更请求。
stateTable2qpi_rsp (stream<stateTableEntry>&)：状态表的响应流，用于从状态表中获取当前 QP 的状态。
qpi2stateTable_upd_req (stream<ifStateReq>&)：发送给状态表的更新请求流，用于请求更新 QP 的状态。
if2msnTable_init (stream<ifMsnReq>&)：发送给 MSN 表的初始化请求流，用于初始化 MSN 表。
*/
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"qp_interface 函数开始执行"<<std::endl;
	enum fstStateType
	{
		GET_STATE,
		UPD_STATE
	};
	static fstStateType qp_fsmState = GET_STATE;
	static qpContext context;
	stateTableEntry state;

	switch (qp_fsmState)
	{
	case GET_STATE:
		if (!contextIn.empty())
		{
			contextIn.read(context);
			qpi2stateTable_upd_req.write(context.qp_num);
			qp_fsmState = UPD_STATE;
		}
		break;
	case UPD_STATE:
		if (!stateTable2qpi_rsp.empty())
		{
			stateTable2qpi_rsp.read(state);
			// TODO check if valid transition
			qpi2stateTable_upd_req.write(ifStateReq(context.qp_num, context.newState, context.remote_psn, context.local_psn));
			if2msnTable_init.write(ifMsnReq(context.qp_num, context.r_key)); // TODO store virtual address somewhere??
			qp_fsmState = GET_STATE;
		}
		break;
	}
}

void three_merger(stream<event> &in0, stream<event> &in1, stream<event> &in2, stream<event> &out)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"three_merger 函数开始执行"<<std::endl;
	if (!in0.empty())
	{
		out.write(in0.read());
	}
	else if (!in1.empty())
	{
		out.write(in1.read());
	}
	else if (!in2.empty())
	{
		out.write(in2.read());
	}
}

template <int WIDTH>
void mem_cmd_merger(stream<memCmdInternal> &remoteReadRequests,
					stream<memCmdInternal> &localReadRequests,
					stream<routedMemCmd> &out,
					stream<pkgInfo> &pkgInfoFifo)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"mem_cmd_merger 函数开始执行"<<std::endl;
	memCmdInternal cmd;

	if (!remoteReadRequests.empty())
	{
		remoteReadRequests.read(cmd);
		out.write(routedMemCmd(cmd.addr, cmd.len, cmd.route));
#if POINTER_CHASING_EN
		if (cmd.route == ROUTE_CUSTOM)
		{
			pkgInfoFifo.write(pkgInfo(AETH, FIFO, ((cmd.len + (WIDTH / 8) - 1) / (WIDTH / 8))));
		}
		else
#endif
		{
			pkgInfoFifo.write(pkgInfo(AETH, MEM, ((cmd.len + (WIDTH / 8) - 1) / (WIDTH / 8))));
		}
	}
	else if (!localReadRequests.empty())
	{
		localReadRequests.read(cmd);
		// CHECK if data in memory
		if (cmd.addr != 0)
		{
			out.write(routedMemCmd(cmd.addr, cmd.len, cmd.route));
			pkgInfoFifo.write(pkgInfo(RETH, MEM, ((cmd.len + (WIDTH / 8) - 1) / (WIDTH / 8))));
		}
		else
		{
			pkgInfoFifo.write(pkgInfo(RETH, FIFO, ((cmd.len + (WIDTH / 8) - 1) / (WIDTH / 8))));
		}
	}
}

void merge_retrans_request(stream<retransMeta> &tx2retrans_insertMeta,
						   stream<retransAddrLen> &tx2retrans_insertAddrLen,
						   stream<retransEntry> &tx2retrans_insertRequest)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"merge_retrans_request 函数开始执行"<<std::endl;
	retransMeta meta;
	retransAddrLen addrlen;

	if (!tx2retrans_insertMeta.empty() && !tx2retrans_insertAddrLen.empty())
	{
		tx2retrans_insertMeta.read(meta);
		tx2retrans_insertAddrLen.read(addrlen);
		tx2retrans_insertRequest.write(retransEntry(meta, addrlen));
	}
}

template <int WIDTH>
void merge_rx_pkgs(stream<pkgShiftType> &rx_pkgShiftTypeFifo,
				   stream<net_axis<WIDTH>> &rx_aethSift2mergerFifo,
				   stream<routed_net_axis<WIDTH>> &rx_rethSift2mergerFifo,
				   stream<routed_net_axis<WIDTH>> &rx_NoSift2mergerFifo,
				   stream<routed_net_axis<WIDTH>> &m_axis_mem_write_data)
{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"merge_rx_pkgs 函数开始执行"<<std::endl;
	enum mrpStateType
	{
		IDLE,
		FWD_AETH,
		FWD_RETH,
		FWD_NONE
	};
	static mrpStateType state = IDLE;

	pkgShiftType type;

	switch (state)
	{
	case IDLE:
		if (!rx_pkgShiftTypeFifo.empty())
		{
			rx_pkgShiftTypeFifo.read(type);
			if (type == SHIFT_AETH)
			{
				state = FWD_AETH;
			}
			else if (type == SHIFT_RETH)
			{
				state = FWD_RETH;
			}
			else
			{
				state = FWD_NONE;
			}
		}
		break;
	case FWD_AETH:
		if (!rx_aethSift2mergerFifo.empty())
		{
			net_axis<WIDTH> currWord;
			rx_aethSift2mergerFifo.read(currWord);
			m_axis_mem_write_data.write(routed_net_axis<WIDTH>(currWord, ROUTE_DMA));
			if (currWord.last)
			{
				state = IDLE;
			}
		}
		break;
	case FWD_RETH:
		if (!rx_rethSift2mergerFifo.empty())
		{
			routed_net_axis<WIDTH> currWord;
			rx_rethSift2mergerFifo.read(currWord);
			m_axis_mem_write_data.write(currWord);
			if (currWord.last)
			{
				state = IDLE;
			}
		}
		break;
	case FWD_NONE:
		if (!rx_NoSift2mergerFifo.empty())
		{
			routed_net_axis<WIDTH> currWord;
			rx_NoSift2mergerFifo.read(currWord);
			m_axis_mem_write_data.write(currWord);
			if (currWord.last)
			{
				state = IDLE;
			}
		}
	} // switch
}

template <int WIDTH>
/*
这段代码实现了一个数据包仲裁器 (tx_pkg_arbiter)，用于根据输入数据包的信息类型，将数据流从不同来源（内存或流输入）转发到相应的输出。它控制了如何在不同的状态下将 RDMA（远程直接内存访问）传输中需要的数据包从输入流正确地转发到输出流。代码通过状态机实现仲裁，支持传输 AETH（应答扩展头）、RETH（读扩展头）和未经封装的原始数据 RAW。

代码功能概述
该函数 tx_pkg_arbiter 使用了一个有限状态机（FSM），通过读取 tx_pkgInfoFifo 队列中传递的信息来决定如何转发数据包。具体的功能可以总结为以下几点：

状态机初始化和状态转换：定义了不同的状态来控制从不同的数据源读取数据并将其发送到正确的输出端口。
数据包类型的分类和处理：处理不同的数据包类型，包括 AETH 应答包、RETH 读写请求包，以及 RAW 类型的数据。
流输入和内存读取源：从两类输入源（s_axis_tx_data 和 s_axis_mem_read_data）读取数据，并根据数据包类型将其写入不同的输出流。
状态机设计
状态机 (mrpStateType) 有以下状态：

IDLE：空闲状态，等待 tx_pkgInfoFifo 中传入包的信息来确定要执行的下一步操作。
FWD_MEM_AETH：从内存读取 AETH 数据包。
FWD_MEM_RETH：从内存读取 RETH 数据包。
FWD_MEM_RAW：从内存读取原始数据。
FWD_STREAM_AETH：从流输入读取 AETH 数据包。
FWD_STREAM_RETH：从流输入读取 RETH 数据包。
FWD_STREAM_RAW：从流输入读取原始数据。
代码逻辑解析
代码中的每一个状态都对应了一个不同的数据处理逻辑，具体功能如下：

1. IDLE 状态
在空闲状态下，函数从 tx_pkgInfoFifo 队列中读取数据包信息 (pkgInfo)：

pkgInfo 包含源（内存或流）和类型（AETH, RETH 等）。
根据包信息设置状态机的状态。
如果数据源是 MEM（内存），则转到 FWD_MEM_AETH 或 FWD_MEM_RETH 状态。
如果数据源是 STREAM，则转到 FWD_STREAM_AETH 或 FWD_STREAM_RETH 状态。
2. FWD_STREAM_AETH 状态
从 s_axis_tx_data 流中读取数据。
通过 wordCounter 计数，跟踪数据字数。
如果到达包的末尾，转到 IDLE 状态。
如果字数达到了 PMTU_WORDS，则将 last 标志置为 1，表示当前字是数据包的最后一个字。
如果还有剩余数据，需要进入 FWD_STREAM_RAW 状态来继续处理。
3. FWD_STREAM_RETH 状态
读取 RETH 类型的数据。
逻辑类似于 FWD_STREAM_AETH，但此时数据流被写入 localReadData。
4. FWD_MEM_AETH 状态
从 s_axis_mem_read_data 中读取数据，处理 AETH 类型数据。
如果到达数据包末尾，则回到 IDLE 状态。
如果还有更多数据需要处理，则状态可能转到 FWD_MEM_RAW 以继续处理剩余数据。
5. FWD_MEM_RETH 状态
处理从内存中读取的 RETH 数据。
和 FWD_MEM_AETH 的逻辑相似，但输出是 localReadData。
如果需要继续读取额外的数据，则会进入 FWD_MEM_RAW。
6. FWD_MEM_RAW 和 FWD_STREAM_RAW 状态
处理剩余的原始数据，输出到 rawPayFifo。
如果达到了 PMTU_WORDS，则设置当前字为最后一个并重置计数器。
根据 info.type，决定是否继续处理 AETH 数据。
关键变量和逻辑
tx_pkgInfoFifo：包信息输入流，包含数据包的源和类型。
currWord：当前读取的数据字（net_axis<WIDTH> 类型）。
wordCounter：用于计数已读取的字数，以确保不会超过 PMTU（传输最大单元）。
WIDTH：模板参数，表示数据字的位宽。
info.words：描述当前包剩余的字数，以确定是否需要继续读取。
数据包转发流程
从不同的输入源中读取数据：
MEM 来源的数据包通过 s_axis_mem_read_data 输入流。
STREAM 来源的数据包通过 s_axis_tx_data 输入流。
根据包的类型确定目标输出流：
如果是 AETH 类型的数据包，则通常需要特殊处理。
RETH 类型的数据包直接写入到相应的目标流。
RAW 数据通常用于传输完整的数据载荷。
通过状态机逐个处理数据字：
处理逻辑包括读取数据、设置 last 标志（表示数据包的结束）、处理原始数据的剩余部分等。
每当数据包完成传输时，状态机会回到 IDLE 状态以准备处理下一个数据包。
总结
状态机的作用：tx_pkg_arbiter 函数通过状态机的设计，实现了从不同来源（内存或流输入）读取 RDMA 数据包并将其正确地传输到合适的输出。
包类型处理：处理不同类型的数据包（AETH 应答、RETH 读请求以及原始数据），确保数据按照正确的协议顺序被转发。
仲裁器的作用：它在不同数据源之间进行仲裁，确保数据按照优先级和顺序传递，从而在传输层实现有效的多源数据管理。
这个代码的目的是在 RDMA 传输中，在多个输入源之间进行有效的仲裁，确保数据包在正确的状态下被转发到合适的输出，以满足 RDMA 协议的传输需求。
*/
void tx_pkg_arbiter(stream<pkgInfo> &tx_pkgInfoFifo,
					stream<codeInfo> &code_info_Fifo,
					stream<codeJudge> &code_judge_Fifo,
					gf256 &gf,
					stream<net_axis<WIDTH>> &s_axis_tx_data,
					stream<net_axis<WIDTH>> &s_axis_mem_read_data,
					stream<net_axis<WIDTH>> &remoteReadData,
					stream<net_axis<WIDTH>> &localReadData,
					stream<net_axis<WIDTH>> &rawPayFifo,
					// stream<codedSuccess>&	 	coded_success_Fifo,
					stream<net_axis<WIDTH>> &tx_repair_Fifo,
					stream<codedIB> &tx_codedIBFifo,
					stream<bool> &tx_isCodedFifo,
					stream<codedExh> &tx_codedExhFifo)

{
#pragma HLS inline off
#pragma HLS pipeline II = 1
	// std::cout<<"tx_pkg_arbiter 函数开始执行"<<std::endl;
	// AETH应答包，RETH读写请求包，RAW未经封装的原始数据
	enum mrpStateType
	{
		IDLE,
		FWD_MEM_AETH,
		FWD_MEM_RETH,
		FWD_MEM_RAW,
		FWD_STREAM_AETH,
		FWD_STREAM_RETH,
		FWD_STREAM_RAW,
		FWD_REPAIR_BUFF
	};
	static mrpStateType state = IDLE;
	static ap_uint<8> wordCounter = 0;
	static codeInfo codeinfo;
	static codeJudge codejudge;
	// 编码缓冲区
	static net_axis<WIDTH> repairbuff[MAX_REPAIR][PMTU_WORDS] = {};
#pragma HLS RESOURCE variable = repairbuff core = RAM_T2P_BRAM
	static pkgInfo info;
	net_axis<WIDTH> currWord;
	// static bool need_code = false;
	// codedSuccess coded_success;
	static bool coded_complete = false;
	static int row = 0;
	static int column = 0;
	static int repairPkg_finish = 0;
	static bool trans_complete = true;
	switch (state)
	{
	case IDLE: // 空闲状态

		std::cout << "IDLE" << std::endl;
		if (!code_judge_Fifo.empty())
		{
			code_judge_Fifo.read(codejudge);
			std::cout << "编码决策信息" << codejudge.needCode << std::endl;
			tx_isCodedFifo.write(codejudge.needCode);
		}
		if (coded_complete)
		{
			std::cout << "编码计算已完成" << std::endl;
			state = FWD_REPAIR_BUFF;
			coded_complete = false;
			break;
		}

		if (!tx_pkgInfoFifo.empty())
		{
			tx_pkgInfoFifo.read(info);
			wordCounter = 0;
			if (!code_info_Fifo.empty() && trans_complete)
			{

				trans_complete = false;
				code_info_Fifo.read(codeinfo);
				std::cout << "/* codeinfo已读取: qp:*/" << codeinfo.qpn << std::endl;
			}
			if (info.source == MEM)
			{
				if (info.type == AETH)
				{
					state = FWD_MEM_AETH;
				}
				else
				{
					state = FWD_MEM_RETH;
				}
			}
			else
			{
				if (info.type == AETH)
				{
					state = FWD_STREAM_AETH;
				}
				else
				{
					state = FWD_STREAM_RETH;
				}
			}
		}
		break;
	case FWD_STREAM_AETH:
		std::cout << "FWD_STREAM_AETH" << std::endl;
		if (!s_axis_tx_data.empty())
		{
			if (codejudge.needCode && wordCounter == 0)
			{
				std::cout << "当前处理的这个数据包需要编码,批次:" << codeinfo.codeBat << std::endl;
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
			}

			s_axis_tx_data.read(currWord);
			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "matrixElement:" << matrixElement << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{
				currWord.last = 1;
				wordCounter = 0;
				info.words -= PMTU_WORDS;
				// Check if next one is READ_RSP_MIDDLE
				if (info.words > PMTU_WORDS)
				{
					state = FWD_STREAM_RAW;
				}
			}
			remoteReadData.write(currWord);
		}
		break;
	case FWD_STREAM_RETH:
		std::cout << "FWD_STREAM_RETH" << std::endl;
		if (!s_axis_tx_data.empty())
		{
			if (codejudge.needCode && wordCounter == 0)
			{
				std::cout << "当前处理的这个数据包需要编码,批次:" << codeinfo.codeBat << std::endl;
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
			}
			s_axis_tx_data.read(currWord);
			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{
				currWord.last = 1;

				wordCounter = 0;
			}
			localReadData.write(currWord);
		}
		break;
	case FWD_MEM_AETH:
		std::cout << "FWD_MEM_AETH" << std::endl;
		if (!s_axis_mem_read_data.empty())
		{
			if (codejudge.needCode && wordCounter == 0)
			{
				std::cout << "当前处理的这个数据包需要编码,批次:" << codeinfo.codeBat << std::endl;
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
			}
			s_axis_mem_read_data.read(currWord);
			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{
				currWord.last = 1;

				wordCounter = 0;
				info.words -= PMTU_WORDS;
				// Check if next one is READ_RSP_MIDDLE
				if (info.words > PMTU_WORDS)
				{
					state = FWD_MEM_RAW;
				}
			}
			remoteReadData.write(currWord);
		}
		break;
	case FWD_MEM_RETH:
		std::cout << "FWD_MEM_RETH" << std::endl;
		if (!s_axis_mem_read_data.empty())
		{
			if (codejudge.needCode && wordCounter == 0)
			{
				std::cout << "当前处理的这个数据包需要编码,批次:" << codeinfo.codeBat << std::endl;
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
			}
			s_axis_mem_read_data.read(currWord);
			std::cout << "RETH DATA FROM MEMORY: ";
			print(std::cout, currWord);
			std::cout << std::endl;

			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{
				currWord.last = 1;
				wordCounter = 0;
				info.words -= PMTU_WORDS;
				state = FWD_MEM_RAW;
			}
			localReadData.write(currWord);
		}
		break;
	case FWD_MEM_RAW:
		std::cout << "FWD_MEM_RAW" << std::endl;
		if (!s_axis_mem_read_data.empty())
		{
			if (codejudge.needCode && wordCounter == 0)
			{
				std::cout << "当前处理的这个数据包需要编码,批次:" << codeinfo.codeBat << std::endl;
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
			}
			s_axis_mem_read_data.read(currWord);
			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{
				currWord.last = 1;
				wordCounter = 0;
				info.words -= PMTU_WORDS;
				if (info.type == AETH && info.words <= PMTU_WORDS)
				{
					state = FWD_MEM_AETH;
				}
			}
			rawPayFifo.write(currWord);
		}
		break;
	case FWD_STREAM_RAW:
		std::cout << "FWD_STREAM_RAW" << std::endl;
		if (!s_axis_tx_data.empty())
		{
			s_axis_tx_data.read(currWord);
			if (codejudge.needCode)
			{
				if (codeinfo.initPkgAll == 1)
				{
					repairbuff[0][wordCounter].data = currWord.data;
					repairbuff[0][wordCounter].last = currWord.last;
				}
				else if (codeinfo.repairPkgAll == 1)
				{
					gf256::gf256_add(repairbuff[0][wordCounter].data, currWord.data);
					if (currWord.last)
					{
						repairbuff[0][wordCounter].keep = currWord.keep;
					}
				}
				else
				{
					const auto x_0 = static_cast<uint8_t>(codeinfo.initPkgAll);
					const auto y_i = static_cast<uint8_t>(codejudge.row);
					for (int i = 0; i < codeinfo.repairPkgAll; i++)
					{
#pragma HLS unroll fctor = MAX_REPAIR
						const auto x_i = static_cast<uint8_t>(i + codeinfo.initPkgAll);
						const uint8_t matrixElement = gf.getMatrixElement(x_i, x_0, y_i);
						std::cout << "当前数据:" << currWord.data << "\t计算前数据:" << repairbuff[i][wordCounter].data;
						gf.gf256_mul_add(repairbuff[i][wordCounter].data, matrixElement, currWord.data);
						std::cout << "\t计算后数据:" << repairbuff[i][wordCounter].data << std::endl;

						if (currWord.last)
						{
							repairbuff[i][wordCounter].keep = currWord.keep;
						}
					}
				}
			}
			wordCounter++;
			std::cout << "当前处理字计数:" << wordCounter << std::endl;
			if (currWord.last)
			{
				state = IDLE;
				if (info.words - wordCounter == 0)
				{
					coded_complete = true;
				}
			}
			if (wordCounter == PMTU_WORDS)
			{

				currWord.last = 1;
				wordCounter = 0;
				info.words -= PMTU_WORDS;
				if (info.type == AETH && info.words <= PMTU_WORDS)
				{
					state = FWD_STREAM_AETH;
				}
			}
			rawPayFifo.write(currWord);
		}
		break;
	case FWD_REPAIR_BUFF:
		std::cout << "FWD_REPAIR_BUFF" << std::endl;
		std::cout << "row:" << row << std::endl;

		if (row < codeinfo.repairPkgAll)
		{
			if (column == PMTU_WORDS - 1)
			{
				repairbuff[row][column].last = 1;
			}
			if (info.type == AETH)
			{
				std::cout << "数据包被写入remoteReadData" << std::endl;
				remoteReadData.write(repairbuff[row][column]);
			}
			else
			{
				std::cout << "数据包被写入localReadData" << std::endl;
				localReadData.write(repairbuff[row][column]);
			}
			// rawPayFifo.write(repairbuff[row][column]);
			std::cout << "repairbuff[" << row << "][" << column << "]:";
			print(std::cout, repairbuff[row][column]);
			std::cout << std::endl;
			if (column == 0 && row < codeinfo.repairPkgAll)
			{
				ap_uint<4> codeId = 0;
				codeId[3] = 1;
				codeId[2] = 1;
				if (row == 0)
				{
					codeId[1] = 1;
				}
				if (row == codeinfo.repairPkgAll - 1)
				{
					codeId[0] = 1;
				}
				if (codeinfo.initPkgAll == 1)
				{
					tx_codedIBFifo.write(codedIB(codeinfo.op_code, codeinfo.qpn, codeId, codeinfo.length, codeinfo.addr));
				}
				else
				{
					tx_codedIBFifo.write(codedIB(codeinfo.op_code, codeinfo.qpn, codeId, codeinfo.length, codeinfo.addr));
					std::cout << "恢复包元数据写入成功" << codeinfo.op_code << "qpn:" << codeinfo.qpn << std::endl;
				}
				tx_codedExhFifo.write(codedExh(codeinfo.codeBat, codeinfo.initPkgAll, codeinfo.repairPkgAll));
				std::cout << "tx_codedExhFifo写入成功:" << "codeinfo.codeBat" << codeinfo.codeBat << "codeinfo.initPkgAll" << codeinfo.initPkgAll << "codeinfo.repairPkgAll" << codeinfo.repairPkgAll << std::endl;
				tx_isCodedFifo.write(true);
			}
			column++;
			if ((codeinfo.initPkgAll == 1 && repairbuff[row][column].last) || column == PMTU_WORDS)
			{
				column = 0;
				row++;
			}
		}
		else
		{
			row = 0;
			column = 0;
			trans_complete = true;
			state = IDLE;
		}

	} // switch
}
// template <int WIDTH>
// void codeComputing(
// 	stream<codeInfo>& code_info_mate,
// 	stream<codeJudge>& code_judge_mate,
// 	stream<net_axis<WIDTH> >& repair_date
// )
// {
// 	enum codestate{JUDGE, FWD_MEM_AETH, FWD_MEM_RETH, FWD_MEM_RAW, FWD_STREAM_AETH, FWD_STREAM_RETH, FWD_STREAM_RAW};
// 	static codestate codestate = JUDGE;
// 	static net_axis<WIDTH>(0,~0,0) repairbuff[PMTU_WORDS][MAX_REPIR];
// 	#pragma HLS RESOURCE variable=meta_table core=RAM_T2P_BRAM
// 	static codeInfo codeinfo;
// 	net_axis<WIDTH> currWord;
// 	switch(codestate)
// 	{
// 		case JUDGE:
// 		    if(!code_info_mate.empty())
// 		    {
// 				code_info_mate.write(codeinfo);

// 		    }
// 	}

// }
template <int WIDTH>
void ib_transport_protocol(			   // RX
	stream<ipUdpMeta> &s_axis_rx_meta, //
	stream<net_axis<WIDTH>> &s_axis_rx_data,
	// stream<net_axis<WIDTH> >&	m_axis_rx_data,
	// TX
	stream<txMeta> &s_axis_tx_meta,
	stream<net_axis<WIDTH>> &s_axis_tx_data,
	stream<ipUdpMeta> &m_axis_tx_meta,
	stream<net_axis<WIDTH>> &m_axis_tx_data,
	// Memory
	stream<routedMemCmd> &m_axis_mem_write_cmd,
	stream<routedMemCmd> &m_axis_mem_read_cmd,
	// stream<mmStatus>&	s_axis_mem_write_status,

	stream<routed_net_axis<WIDTH>> &m_axis_mem_write_data,
	stream<net_axis<WIDTH>> &s_axis_mem_read_data,

	// Interface
	stream<qpContext> &s_axis_qp_interface,
	stream<ifConnReq> &s_axis_qp_conn_interface,

// Pointer chasing
#if POINTER_CHASING_EN
	stream<ptrChaseMeta> &m_axis_rx_pcmeta,
	stream<ptrChaseMeta> &s_axis_tx_pcmeta,
#endif

	ap_uint<32> &regInvalidPsnDropCount,
	ap_uint<64> &rawTime,
	ap_uint<64> &totalTime,
	ap_uint<64> &currCycle)
{
#pragma HLS INLINE

	static stream<net_axis<WIDTH>> rx_ibh2shiftFifo("rx_ibh2shiftFifo");
	static stream<net_axis<WIDTH>> rx_shift2exhFifo("rx_shift2exhFifo");
	static stream<net_axis<WIDTH>> rx_exh2dropFifo("rx_exh2dropFifo");
	static stream<net_axis<WIDTH>> rx_ibhDrop2exhFifo("rx_ibhDrop2exhFifo");
	static stream<ibhMeta> rx_ibh2fsm_MetaFifo("rx_ibh2fsm_MetaFifo");
	static stream<ibhMeta> rx_fsm2exh_MetaFifo("rx_fsm2exh_MetaFifo");
	static stream<routed_net_axis<WIDTH>> rx_exh2rethShiftFifo("rx_exh2rethShiftFifo");
	static stream<net_axis<WIDTH>> rx_exh2aethShiftFifo("rx_exh2aethShiftFifo");
	static stream<routed_net_axis<WIDTH>> rx_exhNoShiftFifo("rx_exhNoShiftFifo");
	static stream<routed_net_axis<WIDTH>> rx_rethSift2mergerFifo("rx_rethSift2mergerFifo");
	static stream<net_axis<WIDTH>> rx_aethSift2mergerFifo("rx_aethSift2mergerFifo");
	static stream<pkgSplitType> rx_pkgSplitTypeFifo("rx_pkgSplitTypeFifo");
	static stream<pkgShiftType> rx_pkgShiftTypeFifo("rx_pkgShiftTypeFifo");
#pragma HLS STREAM depth = 2 variable = rx_ibh2shiftFifo
#pragma HLS STREAM depth = 2 variable = rx_shift2exhFifo
#pragma HLS STREAM depth = 32 variable = rx_exh2dropFifo
#pragma HLS STREAM depth = 32 variable = rx_ibhDrop2exhFifo
#pragma HLS STREAM depth = 2 variable = rx_ibh2fsm_MetaFifo
#pragma HLS STREAM depth = 2 variable = rx_fsm2exh_MetaFifo
#pragma HLS STREAM depth = 4 variable = rx_exh2rethShiftFifo
#pragma HLS STREAM depth = 4 variable = rx_exh2aethShiftFifo
#pragma HLS STREAM depth = 4 variable = rx_exhNoShiftFifo
#pragma HLS STREAM depth = 4 variable = rx_rethSift2mergerFifo
#pragma HLS STREAM depth = 4 variable = rx_aethSift2mergerFifo
#pragma HLS STREAM depth = 2 variable = rx_pkgSplitTypeFifo
#pragma HLS STREAM depth = 2 variable = rx_pkgShiftTypeFifo
#pragma HLS DATA_PACK variable = rx_ibh2fsm_MetaFifo
#pragma HLS DATA_PACK variable = rx_fsm2exh_MetaFifo
#pragma HLS DATA_PACK variable = rx_pkgSplitTypeFifo
#pragma HLS DATA_PACK variable = rx_pkgShiftTypeFifo

	static stream<ackEvent> rx_ibhEventFifo("rx_ibhEventFifo"); // TODO rename
	static stream<ackEvent> rx_exhEventMetaFifo("rx_exhEventMetaFifo");
	static stream<memCmdInternal> rx_remoteMemCmd("rx_remoteMemCmd");
#pragma HLS STREAM depth = 2 variable = rx_ibhEventFifo
#pragma HLS STREAM depth = 2 variable = rx_exhEventMetaFifo
#pragma HLS STREAM depth = 512 variable = rx_remoteMemCmd
#pragma HLS DATA_PACK variable = rx_ibhEventFifo
#pragma HLS DATA_PACK variable = rx_exhEventMetaFifo
#pragma HLS DATA_PACK variable = rx_remoteMemCmd

	static stream<ibhMeta>
		tx_ibhMetaFifo("tx_ibhMetaFifo");
	static stream<event> tx_appMetaFifo("tx_appMetaFifo");
	// static stream<event>	tx_localMetaFifo("tx_localMetaFifo");
	static stream<net_axis<WIDTH>> tx_appDataFifo("tx_appDataFifo");
#pragma HLS STREAM depth = 8 variable = tx_ibhMetaFifo
#pragma HLS STREAM depth = 32 variable = tx_appMetaFifo
// #pragma HLS STREAM depth=8 variable=tx_localMetaFifo
#pragma HLS STREAM depth = 8 variable = tx_appDataFifo

	static stream<codedIB> tx_codedIBFifo("tx_codedIBFifo");
#pragma HLS STREAM depth = 32 variable = tx_codedIBFifo
	static stream<codedExh> tx_codedExhFifo("tx_codedExhFifo");
#pragma HLS STREAM depth = 32 variable = tx_codedExhFifo

	static stream<event> tx_exhMetaFifo("tx_exhMetaFifo");
	static stream<net_axis<WIDTH>> tx_exh2shiftFifo("tx_exh2shiftFifo");
	static stream<net_axis<WIDTH>> tx_shift2ibhFifo("tx_shift2ibhFifo");
	static stream<net_axis<WIDTH>> tx_aethShift2payFifo("tx_aethShift2payFifo");
	static stream<net_axis<WIDTH>> tx_rethShift2payFifo("tx_rethShift2payFifo");
	static stream<net_axis<WIDTH>> tx_rawPayFifo("tx_rawPayFifo");
	static stream<net_axis<WIDTH>> tx_exh2payFifo("tx_exh2payFifo");
	static stream<BaseTransportHeader<WIDTH>> tx_ibhHeaderFifo("tx_ibhHeaderFifo");
	static stream<memCmdInternal> tx_localMemCmdFifo("tx_localMemCmdFifo");
#pragma HLS STREAM depth = 4 variable = tx_exhMetaFifo
#pragma HLS STREAM depth = 2 variable = tx_exh2shiftFifo
#pragma HLS STREAM depth = 8 variable = tx_shift2ibhFifo
#pragma HLS STREAM depth = 2 variable = tx_aethShift2payFifo
#pragma HLS STREAM depth = 2 variable = tx_rethShift2payFifo
#pragma HLS STREAM depth = 4 variable = tx_rawPayFifo
#pragma HLS STREAM depth = 4 variable = tx_exh2payFifo
#pragma HLS STREAM depth = 2 variable = tx_ibhHeaderFifo
#pragma HLS STREAM depth = 2 variable = tx_localMemCmdFifo
#pragma HLS DATA_PACK variable = tx_exhMetaFifo
#pragma HLS DATA_PACK variable = tx_ibhHeaderFifo
#pragma HLS DATA_PACK variable = tx_localMemCmdFifo
	static stream<net_axis<WIDTH>> tx_codedPagketFifo("tx_codedPagketFifo");
#pragma HLS STREAM depth = 2 variable = tx_codedPagketFifo

	static stream<net_axis<WIDTH>> tx_codedshiftFifo("tx_codedshiftFifo");
	static stream<net_axis<WIDTH>> tx_codedcethshiftFifo("tx_codedcethshiftFifo");
	static stream<net_axis<WIDTH>> tx_codedshiftibhFifo("tx_codedshiftibhFifo");
#pragma HLS STREAM depth = 4 variable = tx_codedshiftFifo
#pragma HLS STREAM depth = 4 variable = tx_codedcethshiftFifo
#pragma HLS STREAM depth = 8 variable = tx_codedshiftibhFifo

	static stream<txPacketInfo> tx_packetInfoFifo("tx_packetInfoFifo");
	static stream<ap_uint<16>> tx_lengthFifo("tx_lengthFifo");
#pragma HLS STREAM depth = 2 variable = tx_packetInfoFifo
#pragma HLS STREAM depth = 4 variable = tx_lengthFifo
#pragma HLS DATA_PACK variable = tx_packetInfoFifo

	static stream<bool> rx_ibhDropFifo("rx_ibhDropFifo");
	static stream<fwdPolicy> rx_ibhDropMetaFifo("rx_ibhDropMetaFifo");
#pragma HLS STREAM depth = 2 variable = rx_ibhDropFifo
#pragma HLS STREAM depth = 2 variable = rx_ibhDropMetaFifo
#pragma HLS DATA_PACK variable = rx_ibhDropMetaFifo

	// Connection Table
	static stream<ap_uint<16>> tx_ibhconnTable_req("tx_ibhconnTable_req");
	// static stream<ifConnReq>		qpi2connTable_req("qpi2connTable_req");
	static stream<connTableEntry> tx_connTable2ibh_rsp("tx_connTable2ibh_rsp");
// static stream<connTableEntry> connTable2qpi_rsp("connTable2qpi_rsp");
#pragma HLS STREAM depth = 2 variable = tx_ibhconnTable_req
#pragma HLS STREAM depth = 8 variable = tx_connTable2ibh_rsp
#pragma HLS DATA_PACK variable = tx_connTable2qpi_rsp

	// State Table Fifos
	static stream<rxStateReq> rxIbh2stateTable_upd_req("rxIbh2stateTable_upd_req");
	static stream<txStateReq> txIbh2stateTable_upd_req("txIbh2stateTable_upd_req");
	static stream<ifStateReq> qpi2stateTable_upd_req("qpi2stateTable_upd_req");
	static stream<rxStateRsp> stateTable2rxIbh_rsp("stateTable2rxIbh_rsp");
	static stream<stateTableEntry> stateTable2txIbh_rsp("stateTable2txIbh_rsp");
	static stream<stateTableEntry> stateTable2qpi_rsp("stateTable2qpi_rsp");
#pragma HLS STREAM depth = 2 variable = rxIbh2stateTable_upd_req
#pragma HLS STREAM depth = 2 variable = txIbh2stateTable_upd_req
#pragma HLS STREAM depth = 2 variable = qpi2stateTable_upd_req
#pragma HLS STREAM depth = 2 variable = stateTable2rxIbh_rsp
#pragma HLS STREAM depth = 2 variable = stateTable2txIbh_rsp
#pragma HLS STREAM depth = 2 variable = stateTable2qpi_rsp
#pragma HLS DATA_PACK variable = rxIbh2stateTable_upd_req
#pragma HLS DATA_PACK variable = txIbh2stateTable_upd_req
#pragma HLS DATA_PACK variable = qpi2stateTable_upd_req
#pragma HLS DATA_PACK variable = stateTable2rxIbh_rsp
#pragma HLS DATA_PACK variable = stateTable2txIbh_rsp
#pragma HLS DATA_PACK variable = stateTable2qpi_rsp

	// MSN Table ->message number
	static stream<rxMsnReq> rxExh2msnTable_upd_req("rxExh2msnTable_upd_req");
	static stream<ap_uint<16>> txExh2msnTable_req("txExh2msnTable_req");
	static stream<ifMsnReq> if2msnTable_init("if2msnTable_init");
	static stream<dmaState> msnTable2rxExh_rsp("msnTable2rxExh_rsp");
	static stream<txMsnRsp> msnTable2txExh_rsp("msnTable2txExh_rsp");
#pragma HLS STREAM depth = 2 variable = rxExh2msnTable_upd_req
#pragma HLS STREAM depth = 2 variable = txExh2msnTable_req
#pragma HLS STREAM depth = 2 variable = if2msnTable_init
#pragma HLS STREAM depth = 2 variable = msnTable2rxExh_rsp
#pragma HLS STREAM depth = 2 variable = msnTable2txExh_rsp
#pragma HLS DATA_PACK variable = rxExh2msnTable_upd_req
#pragma HLS DATA_PACK variable = if2msnTable_init
#pragma HLS DATA_PACK variable = msnTable2rxExh_rsp
#pragma HLS DATA_PACK variable = msnTable2txExh_rsp

	static stream<ap_uint<16>> exh_lengthFifo("exh_lengthFifo");
	static stream<readRequest> rx_readRequestFifo("rx_readRequestFifo");
	static stream<event> rx_readEvenFifo("rx_readEvenFifo");
	static stream<ackEvent> rx_ackEventFifo("rx_ackEventFifo");
#pragma HLS STREAM depth = 4 variable = exh_lengthFifo
#pragma HLS STREAM depth = 8 variable = rx_readRequestFifo
#pragma HLS STREAM depth = 512 variable = rx_readEvenFifo
#pragma HLS STREAM depth = 4 variable = rx_ackEventFifo
#pragma HLS DATA_PACK variable = rx_readRequestFifo
#pragma HLS DATA_PACK variable = rx_readEvenFifo
#pragma HLS DATA_PACK variable = rx_ackEventFifo

	// Read Req Table
	static stream<txReadReqUpdate> tx_readReqTable_upd("tx_readReqTable_upd");
	static stream<rxReadReqUpdate> rx_readReqTable_upd_req("rx_readReqTable_upd_req");
	static stream<rxReadReqRsp> rx_readReqTable_upd_rsp("rx_readReqTable_upd_rsp");
#pragma HLS STREAM depth = 2 variable = tx_readReqTable_upd
#pragma HLS STREAM depth = 2 variable = rx_readReqTable_upd_req
#pragma HLS STREAM depth = 2 variable = rx_readReqTable_upd_rsp
#pragma HLS DATA_PACK variable = tx_readReqTable_upd
#pragma HLS DATA_PACK variable = rx_readReqTable_upd_req
#pragma HLS DATA_PACK variable = rx_readReqTable_upd_rsp

	// Outstanding Read Req Table
	// TODO merge these two
	static stream<mqInsertReq<ap_uint<64>>> tx_readReqAddr_push("tx_readReqAddr_push");
	static stream<mqPopReq> rx_readReqAddr_pop_req("rx_readReqAddr_pop_req");
	static stream<ap_uint<64>> rx_readReqAddr_pop_rsp("rx_readReqAddr_pop_rsp");
#pragma HLS STREAM depth = 2 variable = tx_readReqAddr_push
#pragma HLS STREAM depth = 2 variable = rx_readReqAddr_pop_req
#pragma HLS STREAM depth = 2 variable = rx_readReqAddr_pop_rsp
#pragma HLS DATA_PACK variable = rx_readReqAddr_pop_req
#pragma HLS DATA_PACK variable = rx_readReqAddr_pop_rsp

	// 位图信息
	//  static stream<updateBitMap>		updateBitMapFifo("updateBitMapFifo");
	//  static stream<completeBitmap>   completeBitmapFifo("completeBitmapFifo");
	//  static stream<queryCount>       queryCountFifo("queryCountFifo");
	//  static stream<ap_uint<16> >     countFifo("countFifo");
	//  #pragma HLS STREAM depth=2 variable=updateBitMapFifo
	//  #pragma HLS STREAM depth=2 variable=completeBitmapFifo
	//  #pragma HLS STREAM depth=2 variable=queryCountFifo
	//  #pragma HLS STREAM depth=2 variable=countFifo

	/*
	 * TIMER & RETRANSMITTER
	 */
#if RETRANS_EN
	static stream<rxTimerUpdate> rxClearTimer_req("rxClearTimer_req");
	static stream<ap_uint<24>> txSetTimer_req("txSetTimer_req");
	static stream<retransRelease> rx2retrans_release_upd("rx2retrans_release_upd");
	static stream<retransmission> rx2retrans_req("rx2retrans_req");
	static stream<retransmission> timer2retrans_req("timer2retrans_req");
	static stream<retransMeta> tx2retrans_insertMeta("tx2retrans_insertMeta");
	static stream<retransAddrLen> tx2retrans_insertAddrLen("tx2retrans_insertAddrLen");
	static stream<retransEntry> tx2retrans_insertRequest("tx2retrans_insertRequest");
	static stream<retransEvent> retransmitter2exh_eventFifo("retransmitter2exh_eventFifo");
#pragma HLS STREAM depth = 2 variable = rxClearTimer_req
#pragma HLS STREAM depth = 2 variable = txSetTimer_req
#pragma HLS STREAM depth = 2 variable = rx2retrans_release_upd
#pragma HLS STREAM depth = 2 variable = rx2retrans_req
#pragma HLS STREAM depth = 2 variable = timer2retrans_req
#pragma HLS STREAM depth = 2 variable = tx2retrans_insertMeta
#pragma HLS STREAM depth = 8 variable = tx2retrans_insertAddrLen
#pragma HLS STREAM depth = 2 variable = tx2retrans_insertRequest
#pragma HLS STREAM depth = 8 variable = retransmitter2exh_eventFifo
#endif

	// TODO this is a hack
	static stream<ap_uint<24>> tx_dstQpFifo("tx_dstQpFifo");
#pragma HLS STREAM depth = 2 variable = tx_dstQpFifo

	// Interface  更新QP上下文信息

	qp_interface(s_axis_qp_interface, stateTable2qpi_rsp, qpi2stateTable_upd_req, if2msnTable_init);

	/*
	 * RX PATH
	 */
	static stream<ibOpCode> rx_ibh2exh_MetaFifo("rx_ibh2exh_MetaFifo");
	static stream<ExHeader<WIDTH>> rx_exh2drop_MetaFifo("rx_exh2drop_MetaFifo");
	static stream<ExHeader<WIDTH>> rx_drop2exhFsm_MetaFifo("rx_drop2exhFsm_MetaFifo");
	static stream<exhMeta> rx_exhMetaFifo("rx_exhMetaFifo");
#pragma HLS STREAM depth = 2 variable = rx_ibh2exh_MetaFifo
#pragma HLS STREAM depth = 8 variable = rx_exh2drop_MetaFifo
#pragma HLS STREAM depth = 2 variable = rx_drop2exhFsm_MetaFifo
#pragma HLS STREAM depth = 2 variable = rx_exhMetaFifo
#pragma HLS DATA_PACK variable = rx_ibh2exh_MetaFifo
#pragma HLS DATA_PACK variable = rx_exh2drop_MetaFifo
#pragma HLS DATA_PACK variable = rx_drop2exhFsm_MetaFifo
#pragma HLS DATA_PACK variable = rx_exhMetaFifo

	// 接受路径中编码信息元数据跟随
	static stream<bool> rx_isCodedFifo1("rx_isCodedFifo1");
	static stream<bool> rx_isCodedFifo2("rx_isCodedFifo2");
	static stream<net_axis<WIDTH>> rx_shiftcethFifo("rx_shiftcethFifo");
	static stream<net_axis<WIDTH>> rx_shift2cethFifo("rx_shift2cethFifo");
	static stream<cexhMeta> rx_cexhMetaFifo("rx_cexhMetaFifo");
	static stream<ap_uint<16>> rx_codedBatFifo("rx_codedBatFifo");
#pragma HLS STREAM depth = 2 variable = rx_isCodedFifo1
#pragma HLS STREAM depth = 2 variable = rx_isCodedFifo2
#pragma HLS STREAM depth = 2 variable = rx_shiftcethFifo
#pragma HLS STREAM depth = 2 variable = rx_shift2cethFifo
#pragma HLS STREAM depth = 2 variable = rx_cexhMetaFifo
#pragma HLS DATA_PACK variable = rx_cexhMetaFifo
#pragma HLS STREAM depth = 2 variable = rx_codedBatFifo

	/*
	 * TX PATH
	 */

	// application request handler
	static stream<pkgInfo> tx_pkgInfoFifo("tx_pkgInfoFifo");
	// static stream<net_axis<WIDTH> > tx_readDataFifo("tx_readDataFifo");
	static stream<net_axis<WIDTH>> tx_split2aethShift("tx_split2aethShift");
	static stream<net_axis<WIDTH>> tx_split2rethMerge("tx_split2rethMerge");
	static stream<net_axis<WIDTH>> tx_rethMerge2rethShift("tx_rethMerge2rethShift");
#pragma HLS STREAM depth = 128 variable = tx_pkgInfoFifo
// #pragma HLS STREAM depth=4 variable=tx_readDataFifo
#pragma HLS STREAM depth = 4 variable = tx_split2aethShift
#pragma HLS STREAM depth = 4 variable = tx_split2rethMerge
#pragma HLS STREAM depth = 4 variable = tx_rethMerge2rethShift

	// static stream<net_axis<WIDTH> > tx_readDataFifo("tx_readDataFifo");
	static stream<net_axis<WIDTH>> tx_split2codeAethShift("tx_split2codeAethShift");
	static stream<net_axis<WIDTH>> tx_split2codeRethMerge("tx_split2codeRethMerge");
	static stream<net_axis<WIDTH>> tx_rethMerge2codeRethShift("tx_rethMerge2codeRethShift");
// #pragma HLS STREAM depth=4 variable=tx_readDataFifo
#pragma HLS STREAM depth = 4 variable = tx_split2codeAethShift
#pragma HLS STREAM depth = 4 variable = tx_split2codeRethMerge
#pragma HLS STREAM depth = 4 variable = tx_rethMerge2codeRethShift

	static stream<codeInfo> code_info_Fifo("code_info_Fifo");
	static stream<codeJudge> code_judge_Fifo("code_judge_Fifo");
	static stream<bool> tx_isCodedFifo1("tx_isCodedFifo1");
	static stream<bool> tx_isCodedFifo2("tx_isCodedFifo2");
	static stream<bool> tx_isCodedFifo3("tx_isCodedFifo3");
	// static stream<codedSuccess> coded_success_Fifo("coded_success_Fifo");
	static stream<net_axis<WIDTH>> tx_repair_Fifo("tx_repair_Fifo");
#pragma HLS STREAM depth = 1 variable = code_info_Fifo
#pragma HLS STREAM depth = 128 variable = code_judge_Fifo
#pragma HLS STREAM depth = 128 variable = tx_isCodedFifo1
#pragma HLS STREAM depth = 128 variable = tx_isCodedFifo2
#pragma HLS STREAM depth = 128 variable = tx_isCodedFifo3
#pragma HLS STREAM depth = 4 variable = tx_repair_Fifo
	// #pragma HLS STREAM depth=128 variable=coded_success_Fifo
	static gf256 gf;

	// 处理传输请求
	local_req_handler(s_axis_tx_meta,
#if RETRANS_EN
					  retransmitter2exh_eventFifo,
#endif
					  tx_localMemCmdFifo,
					  gf,
					  tx_readReqAddr_push,
					  code_info_Fifo,
					  code_judge_Fifo,
#if !RETRANS_EN
					  tx_appMetaFifo);
#else
					  tx_appMetaFifo,
					  tx2retrans_insertAddrLen);
#endif

// Only used when FPGA does standalon, currently disabled
#ifdef FPGA_STANDALONE
	fpga_data_handler(s_axis_tx_data, tx_appDataFifo);
#endif

	// 取数据  将编码后的包输出到一个流，生成codedExh并追加和后，再根据opcode
	tx_pkg_arbiter(tx_pkgInfoFifo,
				   code_info_Fifo,
				   code_judge_Fifo,
				   gf,
				   s_axis_tx_data,
				   s_axis_mem_read_data,
				   tx_split2aethShift,
#ifdef FPGA_STANDALONE
				   tx_split2rethMerge);
#else
				   tx_rethMerge2rethShift,
#endif
					tx_rawPayFifo,
					// coded_success_Fifo,
					tx_repair_Fifo,
					tx_codedIBFifo,
					tx_isCodedFifo1,
					tx_codedExhFifo);

#ifdef FPGA_STANDALONE
					stream_merger(tx_split2rethMerge, tx_appDataFifo, tx_rethMerge2rethShift);
#endif
					// merges and orders event going to TX path
					meta_merger(rx_ackEventFifo, rx_readEvenFifo, tx_appMetaFifo, tx_codedIBFifo, tx_ibhconnTable_req, tx_ibhMetaFifo, tx_exhMetaFifo);

					// Shift playload by 4 bytes for AETH (data from memory)  AETH 是一种扩展的传输头部，主要用于 ACK（确认）消息，尤其是在 RDMA写操作的应答（acknowledgement） 中使用。
					lshiftWordByOctet<WIDTH, 12>(((AETH_SIZE % WIDTH) / 8), tx_split2aethShift, tx_aethShift2payFifo);
					// Shift payload another 12 bytes for RETH (data from application)  RETH 是 RDMA 扩展传输头部，用于 RDMA Read 和 RDMA Write 操作 的数据包，携带了 虚拟地址、内存长度和R_Key 等重要信息。
					lshiftWordByOctet<WIDTH, 13>(((RETH_SIZE % WIDTH) / 8), tx_rethMerge2rethShift, tx_rethShift2payFifo);
					msn_table(rxExh2msnTable_upd_req,
							  txExh2msnTable_req,
							  if2msnTable_init,
							  msnTable2rxExh_rsp,
							  msnTable2txExh_rsp);
					// Generate EXH
					generate_exh(tx_exhMetaFifo,
								 tx_isCodedFifo1,
#if POINTER_CHASING_EN
								 s_axis_tx_pcmeta,
#endif
								 msnTable2txExh_rsp,
								 txExh2msnTable_req,
								 tx_readReqTable_upd,
								 tx_lengthFifo,
								 tx_packetInfoFifo,
								 tx_isCodedFifo2,
#if RETRANS_EN
								 txSetTimer_req,
#endif
								 tx_exh2payFifo);
					// std::cout<<"append_payload开始"<<std::endl;
					// Append payload to AETH or RETH
					append_payload(tx_packetInfoFifo, tx_isCodedFifo2, tx_isCodedFifo3, tx_exh2payFifo, tx_aethShift2payFifo, tx_rethShift2payFifo, tx_rawPayFifo, tx_codedPagketFifo, tx_exh2shiftFifo);
					// std::cout<<"lshiftWordByOctet开始"<<std::endl;
					lshiftWordByOctet<WIDTH, 15>(((CETH_SIZE % WIDTH) / 8), tx_codedPagketFifo, tx_codedshiftFifo);
					// std::cout<<"prepend_ceth_header开始"<<std::endl;
					prepend_ceth_header(tx_codedExhFifo, tx_codedshiftFifo, tx_codedcethshiftFifo);
					// BTH: 12 bytes
					// std::cout<<"lshiftWordByOctet开始"<<std::endl;
					lshiftWordByOctet<WIDTH, 11>(((BTH_SIZE % WIDTH) / 8), tx_exh2shiftFifo, tx_shift2ibhFifo);
					lshiftWordByOctet<WIDTH, 14>(((BTH_SIZE % WIDTH) / 8), tx_codedcethshiftFifo, tx_codedshiftibhFifo);
					// std::cout<<"generate_ibh开始"<<std::endl;
					generate_ibh(tx_ibhMetaFifo,
								 tx_dstQpFifo,
								 stateTable2txIbh_rsp,
								 txIbh2stateTable_upd_req,
#if RETRANS_EN
								 tx2retrans_insertMeta,
#endif
								 tx_ibhHeaderFifo);
					// std::cout<<"prepend_ibh_header开始"<<std::endl;
					// prependt ib header
					prepend_ibh_header(tx_ibhHeaderFifo, tx_isCodedFifo3, tx_shift2ibhFifo, tx_codedshiftibhFifo, m_axis_tx_data, rawTime, totalTime, currCycle);
					// std::cout<<"tx_ipUdpMetaMerger开始"<<std::endl;
					// Get Meta data for UDP & IP layer
					tx_ipUdpMetaMerger(tx_connTable2ibh_rsp, tx_lengthFifo, m_axis_tx_meta, tx_dstQpFifo);
					// std::cout<<"mem_cmd_merger开始"<<std::endl;

					// merge read requests
					mem_cmd_merger<WIDTH>(rx_remoteMemCmd, tx_localMemCmdFifo, m_axis_mem_read_cmd, tx_pkgInfoFifo);
					// std::cout<<"conn_table开始"<<std::endl;

					// Data structures

					conn_table(tx_ibhconnTable_req,
							   s_axis_qp_conn_interface,
							   tx_connTable2ibh_rsp);

					/*
					管理和存储状态表：使用一个状态表 (state_table)，保存了多个 QP 的状态信息。每个 QP 的状态包含了接收和发送所需的 PSN（Packet Sequence Number）等信息。
					支持多个接口进行状态的更新和查询：有三个主要输入流 (rxIbh2stateTable_upd_req、txIbh2stateTable_upd_req、qpi2stateTable_upd_req)，代表不同模块请求对状态进行更新或查询。
					同时支持读取和写入：状态表的操作分为写入（更新状态）和读取（获取状态），可以处理接收端请求、发送端请求以及 QP 初始化请求。
					输入流
					rxIbh2stateTable_upd_req：接收路径模块的请求，用于更新接收状态或者查询接收状态。
					txIbh2stateTable_upd_req：发送路径模块的请求，用于更新发送状态或者查询发送状态。
					qpi2stateTable_upd_req：QP 初始化或连接请求，用于设置新连接的状态信息或者查询状态。
					输出流：
					stateTable2rxIbh_rsp：用于向接收路径模块返回查询的状态信息。
					stateTable2txIbh_rsp：用于向发送路径模块返回查询的状态信息。
					stateTable2qpi_rsp：用于向 QP 管理模块返回查询的状态信息。
					*/
					// std::cout<<"state_table开始"<<std::endl;
					state_table(rxIbh2stateTable_upd_req,
								txIbh2stateTable_upd_req,
								qpi2stateTable_upd_req,
								stateTable2rxIbh_rsp,
								stateTable2txIbh_rsp,
								stateTable2qpi_rsp);
					// std::cout<<"msn_table"<<std::endl;
					// msn_table(	rxExh2msnTable_upd_req,
					// 			txExh2msnTable_req,
					// 			if2msnTable_init,
					// 			msnTable2rxExh_rsp,
					// 			msnTable2txExh_rsp);

					read_req_table(tx_readReqTable_upd,
#if !RETRANS_EN
								   rx_readReqTable_upd_req);
#else
				   rx_readReqTable_upd_req,
				   rx_readReqTable_upd_rsp);
#endif

					multi_queue<ap_uint<64>, MAX_QPS, 2048>(tx_readReqAddr_push,
															rx_readReqAddr_pop_req,
															rx_readReqAddr_pop_rsp);

#if RETRANS_EN
					merge_retrans_request(tx2retrans_insertMeta, tx2retrans_insertAddrLen, tx2retrans_insertRequest);

					transport_timer(rxClearTimer_req,
									txSetTimer_req,
									timer2retrans_req);

					retransmitter(rx2retrans_release_upd,
								  rx2retrans_req,
								  timer2retrans_req,
								  tx2retrans_insertRequest,
								  retransmitter2exh_eventFifo);
#endif
}

template void ib_transport_protocol<DATA_WIDTH>( // RX
	stream<ipUdpMeta> &s_axis_rx_meta,
	stream<net_axis<DATA_WIDTH>> &s_axis_rx_data,
	// stream<net_axis<DATA_WIDTH> >&	m_axis_rx_data,
	// TX
	stream<txMeta> &s_axis_tx_meta,
	stream<net_axis<DATA_WIDTH>> &s_axis_tx_data,
	stream<ipUdpMeta> &m_axis_tx_meta,
	stream<net_axis<DATA_WIDTH>> &m_axis_tx_data,
	// Memory
	stream<routedMemCmd> &m_axis_mem_write_cmd,
	stream<routedMemCmd> &m_axis_mem_read_cmd,
	// stream<mmStatus>&	s_axis_mem_write_status,

	stream<routed_net_axis<DATA_WIDTH>> &m_axis_mem_write_data,
	stream<net_axis<DATA_WIDTH>> &s_axis_mem_read_data,

	// Interface
	stream<qpContext> &s_axis_qp_interface,
	stream<ifConnReq> &s_axis_qp_conn_interface,

// Pointer chasing
#if POINTER_CHASING_EN
	stream<ptrChaseMeta> &m_axis_rx_pcmeta,
	stream<ptrChaseMeta> &s_axis_tx_pcmeta,
#endif

	ap_uint<32> &regInvalidPsnDropCount,
	ap_uint<64> &rawTime,
	ap_uint<64> &totalTime,
	ap_uint<64> &currCycle);

#include<stdio.h>
#include<string.h>
#include"protocol.h"
#include"datalink.h"

// 设置数据定时器的时间间隔为2000ms
#define DATA_TIMER	2000
// 设置ACK计时器的时间间隔为1100ms
#define ACK_TIMER	1100
// 设置序列最大编号为MAX_SEQ，即编号范围0~MAX_SEQ（并不等于窗口大小）
#define MAX_SEQ 31
// 窗口大小为4
#define NR_BUFS 16
// 宏inc实现自动循环+1
#define inc(k) if (k<MAX_SEQ) k = k + 1; else k = 0;

// 帧类型：数据帧、ACK帧还是NAK帧
typedef unsigned char frame_kind;

// 帧的序号
typedef unsigned char seq_nr;

// 限制数据包的大小，规定数据包长度固定为256字节
typedef struct {
	unsigned char data[PKT_LEN];
}packet;

// 定义布尔类型
typedef enum { false, true } bool; 

// 定义帧的结构 kind用于区分帧种类，ack和seq分别都带有编号，info表示封装的数据包，同时帧尾部有校验码
typedef struct {
	frame_kind kind;  // 1 byte
	seq_nr ack;  // 1 byte  此处把ack放在帧内部是因为使用了捎带确认的机制
	seq_nr seq;  // 1 byte
	packet info;  // 256 byte
	// 当帧类型为ack或nak时，crc32放在info和seq的位置，因为ack帧的info和seq均没有意义
	unsigned int crc32; // 4 byte
	
}frame;

// 初始化
// 初始时认为物理层缓存已经满了
int phl_ready = 0;
// 初始化NAK序号为1（因为对应上一数据帧的序号是0，但实际上上一个数据帧不存在）
static unsigned char no_nak = 1;

// 判断帧是否按照顺序到达，return ture if a<=b<c
static unsigned char between(seq_nr a, seq_nr b, seq_nr c) {
	return ((a <= b && b < c) || (c < a&& b < c) || (c < a&& a <= b));
}

//封装成帧-帧尾，添加校验和并传送给物理层
static void put_frame(unsigned char* frame, int len)
{
	// 添加32bit(4B)的校验位
	*(unsigned int*)(frame + len) = crc32(frame, len);
	// 将该帧发送给物理层，这里假设物理层缓存是空的没有等待队列即phl_ready = 1
	send_frame(frame, len + 4);
	// 每次发完，假设物理层缓存已满（物理层发送队列的长度大于50字节）
	phl_ready = 0;
}

// 封装成帧
static void send_data(frame_kind fk, seq_nr frame_nr, seq_nr frame_expected, packet buffer[]) {
	// 帧首部
	frame s;
	s.kind = fk;
	// 通过frame_expected倒推计算最近收到的帧的序号，作为ack捎带返回
	s.ack = (frame_expected + MAX_SEQ) % (MAX_SEQ + 1);
	// ack已捎带,停止ACK计时器的计时。
	stop_ack_timer();

	// 帧数据部分info
	// 假如这是一个数据帧，正常封装
	if (fk == FRAME_DATA) {      
		// frame_nr为帧序号
		s.seq = frame_nr;
		// 从buffer队列中取出packet进行封装并发送
		memcpy(s.info.data, buffer[frame_nr % NR_BUFS].data, PKT_LEN);
		// 输出调试信息-“帧收发”，每发送和接收一帧，都打印出相关调试信息便于协议分析
		dbg_frame("Send DATA %d %d, ID %d\n", s.seq, s.ack, *(short*)s.info.data);
		// 添加帧尾部并发送到物理层，3+PKT_LEN是因为封装过程中额外kind ack seq三个字节以及数据包的长度
		put_frame((unsigned char*)&s, 3 + PKT_LEN);
		// 发送完毕后数据计时器开始计时
		start_timer(frame_nr % NR_BUFS, DATA_TIMER);
	}
	// 假如这是一个ACK的帧就不需要封装了
	else if (fk == FRAME_ACK) {
		// 输出调试信息-“帧收发”
		dbg_frame("Send ACK  %d\n", s.ack);
		// 在ack后插入4字节crc，覆盖seq和info，2是因为封装过程中额外kind ack两个字节的长度
		put_frame((unsigned char*)&s, 2);
	}
	// 假如这是一个NAK否定帧也不需要封装
	else if (fk == FRAME_NAK) {
		// 输出调试信息-“帧收发”
		dbg_frame("Send NAK  %d\n", (s.ack + 1) % (MAX_SEQ + 1));
		// 出错帧NAK的序号为上一个成功帧的序号r.ack的下一帧
		no_nak = 0;
		// 在ack后插入4字节crc，覆盖seq和info
		put_frame((unsigned char*)&s, 2);
	}
}



int main(int argc, char** argv) {
	// 下一个即将发送的帧序号
	seq_nr next_frame_to_send;  
	// 下一个准备接收的ack序号
	seq_nr ack_expected;  
	//下一个准备接收的帧序号
	seq_nr frame_expected;  
	// 接收窗口的上界
	seq_nr max_frame;  
	frame r;
	// 用于缓存将要发送的数据包 发送窗口
	packet buffer[NR_BUFS];  
	// 接收窗口
	packet in_buffer[NR_BUFS]; 
	// 发送窗口的缓存区，用于缓存发送出去但还没收到ack的帧
	seq_nr nbuffered;  
	// 窗口中的帧是否到达的数组
	bool arrived[NR_BUFS];  

	// 事件event （arg是为了输出timeout时的序号-用于debug）
	int event, arg;  
	// 数据帧的长度
	int len = 0;  

	// 协议初始化
	protocol_init(argc, argv);	
	
	lprintf(" selective_repeat: ACK_TIMER=%dms,  DATA_TIMER=%dms NAK enabled\n", ACK_TIMER, DATA_TIMER);
	lprintf("Designed by HeYixiao, build: " __DATE__"  "__TIME__"\n");

	// 初始化参数和过程
	// 先关闭网络层
	disable_network_layer();  
	ack_expected = 0;			
	next_frame_to_send = 0;		
	frame_expected = 0;
	// 发送窗口缓存为空，因为此时一个帧也没有发送过
	nbuffered = 0;				
	max_frame = NR_BUFS;

	for (int i = 0; i < NR_BUFS; i++)
		arrived[i] = false;

	// 无限循环实现一直通信
	while (true) {                
		// 阻塞等待事件到达
		event = wait_for_event(&arg); 

		switch (event) {

		// 当网络层有新的分组需要发送并且未被链路层 disable
		case NETWORK_LAYER_READY:
			get_packet(buffer[next_frame_to_send % NR_BUFS].data);
			// 将该数据包加入发送窗口缓存
			nbuffered++;         
			send_data(FRAME_DATA, next_frame_to_send, frame_expected, buffer);
			// 发送窗口准备发送下一个缓存区的数据
			inc(next_frame_to_send);				
			break;

		// 物理层准备好了
		case PHYSICAL_LAYER_READY:
			// 设置并保存该物理层状态
			phl_ready = 1;		  
			break;

		// 物理层收到了一个帧（未知帧是否出现误码，未知该帧是什么类型的帧，这些都在后面判断中）
		case FRAME_RECEIVED:
			len = recv_frame((unsigned char*)&r, sizeof(r));

			// 判断crc是否出错
			// 帧最小是6个字节-ack的长度由4字节的crc和1字节的kind以及1字节的ack构成
			if (len < 6 || crc32((unsigned char*)&r, len) != 0) {	
				dbg_event("**** Receiver Error(length=%d), Bad CRC Checksum\n", len);
				if (no_nak)
					send_data(FRAME_NAK, 0, frame_expected, buffer);
				break;
			}

			// 假如crc没出错，接下来判断这是什么类型的帧
			// 假如接收到的是数据帧
			if (r.kind == FRAME_DATA) {
				dbg_frame("Recv DATA %d %d, ID %d --%dbyte\n", r.seq, r.ack, *(short*)r.info.data, len);

				// 假如该帧的序号符合接收窗口希望收到的序号
				if (r.seq == frame_expected) {		
					dbg_frame("True index.\n");
					// 开始ACK计时器
					start_ack_timer(ACK_TIMER);
				}

				// 没有按照顺序到达，返回NAK
				else if (no_nak) {
					dbg_frame("Wrong seqnr %d received,send NAK.\n", r.seq);
					send_data(FRAME_NAK, 0, frame_expected, buffer);
					break;
				}
				// 将接收窗口的可滑动的数据传入网络层
				if (between(frame_expected, r.seq, max_frame) && (arrived[r.seq % NR_BUFS] == false)) {
					// 该帧到达
					arrived[r.seq % NR_BUFS] = true;

					in_buffer[r.seq % NR_BUFS] = r.info;

					// 滑动窗口移动
					while (arrived[frame_expected % NR_BUFS]) {
						dbg_frame("Recv DATA %d %d, ID %d\n", r.seq, r.ack, *(short*)r.info.data);
						put_packet(in_buffer[frame_expected % NR_BUFS].data, len - 7);
						no_nak = 1;
						arrived[frame_expected % NR_BUFS] = false;
						inc(frame_expected);
						inc(max_frame);
						start_ack_timer(ACK_TIMER);
					}
				}
			}

			// 假如接收到的是NAK帧则重传缓存区内的分组
			if (r.kind == FRAME_NAK && between(ack_expected, (r.ack + 1) % (MAX_SEQ + 1), next_frame_to_send)) {
				dbg_frame("Recv NAK  %d --%dbyte\n", (r.ack + 1) % (MAX_SEQ + 1), len);
				send_data(FRAME_DATA, (r.ack + 1) % (MAX_SEQ + 1), frame_expected, buffer);
			}

			// 假如接收到的是ACK帧则滑动发送窗口，将收到ACK对应的帧从缓存中删除
			if (r.kind == FRAME_ACK)
				dbg_frame("Recv ACK  %d --%dbyte\n", r.ack, len);

			while (between(ack_expected, r.ack, next_frame_to_send)) {
				nbuffered--;
				// 数据计时器停止计时
				stop_timer(ack_expected % NR_BUFS);
				// 循环+1
				inc(ack_expected);		
			}
			break;

		// 数据计时器超时，重新发送期待收到ack的帧(超时的帧)
		case DATA_TIMEOUT:							
			dbg_event("---- DATA %d timeout\n", arg);
			// 因为滑动窗口仅为序列数的一半，arg为滑动窗口内的编号，故可能实际超时的帧为arg + NR_BUFS号帧
			if (!between(ack_expected, arg, next_frame_to_send))
				arg = arg + NR_BUFS;
			send_data(FRAME_DATA, arg, frame_expected, buffer);
			break;
		// ACK计时器超时，重新发送ACK
		case ACK_TIMEOUT:                           
			dbg_event("---- ACK %d timeout\n", arg);
			
			send_data(FRAME_ACK, 0, frame_expected, buffer);
			break;
		}

		// 最后需要判断一下是否需要控制网络层的流量（根据数据链路层的发送窗口缓存是否满了来判断）
		if (nbuffered < NR_BUFS && phl_ready)
			enable_network_layer();
		else
			disable_network_layer();
	}
}



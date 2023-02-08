#include<stdio.h>
#include<string.h>
#include"protocol.h"
#include"datalink.h"

// �������ݶ�ʱ����ʱ����Ϊ2000ms
#define DATA_TIMER	2000
// ����ACK��ʱ����ʱ����Ϊ1100ms
#define ACK_TIMER	1100
// �������������ΪMAX_SEQ������ŷ�Χ0~MAX_SEQ���������ڴ��ڴ�С��
#define MAX_SEQ 31
// ���ڴ�СΪ4
#define NR_BUFS 16
// ��incʵ���Զ�ѭ��+1
#define inc(k) if (k<MAX_SEQ) k = k + 1; else k = 0;

// ֡���ͣ�����֡��ACK֡����NAK֡
typedef unsigned char frame_kind;

// ֡�����
typedef unsigned char seq_nr;

// �������ݰ��Ĵ�С���涨���ݰ����ȹ̶�Ϊ256�ֽ�
typedef struct {
	unsigned char data[PKT_LEN];
}packet;

// ���岼������
typedef enum { false, true } bool; 

// ����֡�Ľṹ kind��������֡���࣬ack��seq�ֱ𶼴��б�ţ�info��ʾ��װ�����ݰ���ͬʱ֡β����У����
typedef struct {
	frame_kind kind;  // 1 byte
	seq_nr ack;  // 1 byte  �˴���ack����֡�ڲ�����Ϊʹ�����Ӵ�ȷ�ϵĻ���
	seq_nr seq;  // 1 byte
	packet info;  // 256 byte
	// ��֡����Ϊack��nakʱ��crc32����info��seq��λ�ã���Ϊack֡��info��seq��û������
	unsigned int crc32; // 4 byte
	
}frame;

// ��ʼ��
// ��ʼʱ��Ϊ����㻺���Ѿ�����
int phl_ready = 0;
// ��ʼ��NAK���Ϊ1����Ϊ��Ӧ��һ����֡�������0����ʵ������һ������֡�����ڣ�
static unsigned char no_nak = 1;

// �ж�֡�Ƿ���˳�򵽴return ture if a<=b<c
static unsigned char between(seq_nr a, seq_nr b, seq_nr c) {
	return ((a <= b && b < c) || (c < a&& b < c) || (c < a&& a <= b));
}

//��װ��֡-֡β�����У��Ͳ����͸������
static void put_frame(unsigned char* frame, int len)
{
	// ���32bit(4B)��У��λ
	*(unsigned int*)(frame + len) = crc32(frame, len);
	// ����֡���͸�����㣬�����������㻺���ǿյ�û�еȴ����м�phl_ready = 1
	send_frame(frame, len + 4);
	// ÿ�η��꣬��������㻺������������㷢�Ͷ��еĳ��ȴ���50�ֽڣ�
	phl_ready = 0;
}

// ��װ��֡
static void send_data(frame_kind fk, seq_nr frame_nr, seq_nr frame_expected, packet buffer[]) {
	// ֡�ײ�
	frame s;
	s.kind = fk;
	// ͨ��frame_expected���Ƽ�������յ���֡����ţ���Ϊack�Ӵ�����
	s.ack = (frame_expected + MAX_SEQ) % (MAX_SEQ + 1);
	// ack���Ӵ�,ֹͣACK��ʱ���ļ�ʱ��
	stop_ack_timer();

	// ֡���ݲ���info
	// ��������һ������֡��������װ
	if (fk == FRAME_DATA) {      
		// frame_nrΪ֡���
		s.seq = frame_nr;
		// ��buffer������ȡ��packet���з�װ������
		memcpy(s.info.data, buffer[frame_nr % NR_BUFS].data, PKT_LEN);
		// ���������Ϣ-��֡�շ�����ÿ���ͺͽ���һ֡������ӡ����ص�����Ϣ����Э�����
		dbg_frame("Send DATA %d %d, ID %d\n", s.seq, s.ack, *(short*)s.info.data);
		// ���֡β�������͵�����㣬3+PKT_LEN����Ϊ��װ�����ж���kind ack seq�����ֽ��Լ����ݰ��ĳ���
		put_frame((unsigned char*)&s, 3 + PKT_LEN);
		// ������Ϻ����ݼ�ʱ����ʼ��ʱ
		start_timer(frame_nr % NR_BUFS, DATA_TIMER);
	}
	// ��������һ��ACK��֡�Ͳ���Ҫ��װ��
	else if (fk == FRAME_ACK) {
		// ���������Ϣ-��֡�շ���
		dbg_frame("Send ACK  %d\n", s.ack);
		// ��ack�����4�ֽ�crc������seq��info��2����Ϊ��װ�����ж���kind ack�����ֽڵĳ���
		put_frame((unsigned char*)&s, 2);
	}
	// ��������һ��NAK��֡Ҳ����Ҫ��װ
	else if (fk == FRAME_NAK) {
		// ���������Ϣ-��֡�շ���
		dbg_frame("Send NAK  %d\n", (s.ack + 1) % (MAX_SEQ + 1));
		// ����֡NAK�����Ϊ��һ���ɹ�֡�����r.ack����һ֡
		no_nak = 0;
		// ��ack�����4�ֽ�crc������seq��info
		put_frame((unsigned char*)&s, 2);
	}
}



int main(int argc, char** argv) {
	// ��һ���������͵�֡���
	seq_nr next_frame_to_send;  
	// ��һ��׼�����յ�ack���
	seq_nr ack_expected;  
	//��һ��׼�����յ�֡���
	seq_nr frame_expected;  
	// ���մ��ڵ��Ͻ�
	seq_nr max_frame;  
	frame r;
	// ���ڻ��潫Ҫ���͵����ݰ� ���ʹ���
	packet buffer[NR_BUFS];  
	// ���մ���
	packet in_buffer[NR_BUFS]; 
	// ���ʹ��ڵĻ����������ڻ��淢�ͳ�ȥ����û�յ�ack��֡
	seq_nr nbuffered;  
	// �����е�֡�Ƿ񵽴������
	bool arrived[NR_BUFS];  

	// �¼�event ��arg��Ϊ�����timeoutʱ�����-����debug��
	int event, arg;  
	// ����֡�ĳ���
	int len = 0;  

	// Э���ʼ��
	protocol_init(argc, argv);	
	
	lprintf(" selective_repeat: ACK_TIMER=%dms,  DATA_TIMER=%dms NAK enabled\n", ACK_TIMER, DATA_TIMER);
	lprintf("Designed by HeYixiao, build: " __DATE__"  "__TIME__"\n");

	// ��ʼ�������͹���
	// �ȹر������
	disable_network_layer();  
	ack_expected = 0;			
	next_frame_to_send = 0;		
	frame_expected = 0;
	// ���ʹ��ڻ���Ϊ�գ���Ϊ��ʱһ��֡Ҳû�з��͹�
	nbuffered = 0;				
	max_frame = NR_BUFS;

	for (int i = 0; i < NR_BUFS; i++)
		arrived[i] = false;

	// ����ѭ��ʵ��һֱͨ��
	while (true) {                
		// �����ȴ��¼�����
		event = wait_for_event(&arg); 

		switch (event) {

		// ����������µķ�����Ҫ���Ͳ���δ����·�� disable
		case NETWORK_LAYER_READY:
			get_packet(buffer[next_frame_to_send % NR_BUFS].data);
			// �������ݰ����뷢�ʹ��ڻ���
			nbuffered++;         
			send_data(FRAME_DATA, next_frame_to_send, frame_expected, buffer);
			// ���ʹ���׼��������һ��������������
			inc(next_frame_to_send);				
			break;

		// �����׼������
		case PHYSICAL_LAYER_READY:
			// ���ò�����������״̬
			phl_ready = 1;		  
			break;

		// ������յ���һ��֡��δ֪֡�Ƿ�������룬δ֪��֡��ʲô���͵�֡����Щ���ں����ж��У�
		case FRAME_RECEIVED:
			len = recv_frame((unsigned char*)&r, sizeof(r));

			// �ж�crc�Ƿ����
			// ֡��С��6���ֽ�-ack�ĳ�����4�ֽڵ�crc��1�ֽڵ�kind�Լ�1�ֽڵ�ack����
			if (len < 6 || crc32((unsigned char*)&r, len) != 0) {	
				dbg_event("**** Receiver Error(length=%d), Bad CRC Checksum\n", len);
				if (no_nak)
					send_data(FRAME_NAK, 0, frame_expected, buffer);
				break;
			}

			// ����crcû�����������ж�����ʲô���͵�֡
			// ������յ���������֡
			if (r.kind == FRAME_DATA) {
				dbg_frame("Recv DATA %d %d, ID %d --%dbyte\n", r.seq, r.ack, *(short*)r.info.data, len);

				// �����֡����ŷ��Ͻ��մ���ϣ���յ������
				if (r.seq == frame_expected) {		
					dbg_frame("True index.\n");
					// ��ʼACK��ʱ��
					start_ack_timer(ACK_TIMER);
				}

				// û�а���˳�򵽴����NAK
				else if (no_nak) {
					dbg_frame("Wrong seqnr %d received,send NAK.\n", r.seq);
					send_data(FRAME_NAK, 0, frame_expected, buffer);
					break;
				}
				// �����մ��ڵĿɻ��������ݴ��������
				if (between(frame_expected, r.seq, max_frame) && (arrived[r.seq % NR_BUFS] == false)) {
					// ��֡����
					arrived[r.seq % NR_BUFS] = true;

					in_buffer[r.seq % NR_BUFS] = r.info;

					// ���������ƶ�
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

			// ������յ�����NAK֡���ش��������ڵķ���
			if (r.kind == FRAME_NAK && between(ack_expected, (r.ack + 1) % (MAX_SEQ + 1), next_frame_to_send)) {
				dbg_frame("Recv NAK  %d --%dbyte\n", (r.ack + 1) % (MAX_SEQ + 1), len);
				send_data(FRAME_DATA, (r.ack + 1) % (MAX_SEQ + 1), frame_expected, buffer);
			}

			// ������յ�����ACK֡�򻬶����ʹ��ڣ����յ�ACK��Ӧ��֡�ӻ�����ɾ��
			if (r.kind == FRAME_ACK)
				dbg_frame("Recv ACK  %d --%dbyte\n", r.ack, len);

			while (between(ack_expected, r.ack, next_frame_to_send)) {
				nbuffered--;
				// ���ݼ�ʱ��ֹͣ��ʱ
				stop_timer(ack_expected % NR_BUFS);
				// ѭ��+1
				inc(ack_expected);		
			}
			break;

		// ���ݼ�ʱ����ʱ�����·����ڴ��յ�ack��֡(��ʱ��֡)
		case DATA_TIMEOUT:							
			dbg_event("---- DATA %d timeout\n", arg);
			// ��Ϊ�������ڽ�Ϊ��������һ�룬argΪ���������ڵı�ţ��ʿ���ʵ�ʳ�ʱ��֡Ϊarg + NR_BUFS��֡
			if (!between(ack_expected, arg, next_frame_to_send))
				arg = arg + NR_BUFS;
			send_data(FRAME_DATA, arg, frame_expected, buffer);
			break;
		// ACK��ʱ����ʱ�����·���ACK
		case ACK_TIMEOUT:                           
			dbg_event("---- ACK %d timeout\n", arg);
			
			send_data(FRAME_ACK, 0, frame_expected, buffer);
			break;
		}

		// �����Ҫ�ж�һ���Ƿ���Ҫ��������������������������·��ķ��ʹ��ڻ����Ƿ��������жϣ�
		if (nbuffered < NR_BUFS && phl_ready)
			enable_network_layer();
		else
			disable_network_layer();
	}
}



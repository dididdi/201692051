
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Thomas Lopatic (thomas@lopatic.de)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of olsr.org, olsrd nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Visit http://www.olsr.org for more information.
 *
 * If you find this software useful feel free to make a donation
 * to the project. For more information see the website or contact
 * the copyright holders.
 *
 */

#ifndef _OLSR_LQ_PACKET_H
#define _OLSR_LQ_PACKET_H

#include "olsr_types.h"
#include "packet.h"
#include "mantissa.h"
#include "ipcalc.h"

#define LQ_HELLO_MESSAGE      201
#define LQ_TC_MESSAGE         202

/* deserialized OLSR header */

struct olsr_common {
  uint8_t type;                 //取值在0~127之间，此数表示MEssage是哪种类型的
  olsr_reltime vtime;          //该属性表示收到该消息的节点认为该消息有效的时间，其计算公式为
                               //validity time = C*(1+a/16)* 2^b  [in seconds]
                               //其中a=是vtime的高4位，b是vtime的低四位
  uint16_t size;              //表示消息的大小
  union olsr_ip_addr orig;    //此域包含产生该消息的节点的主地址
                               //这里应避免与 IP报头里的源地址混淆，后者要每次变更为中间重传消息节点的接口地址。前者在重传中永远不会变化。
  uint8_t ttl;                //time to live
  uint8_t hops;                //消息的跳数
  uint16_t seqno;                //产生此消息的节点会指派一个唯一的标识号，每生成一个消息，序列号+
};

/* serialized IPv4 OLSR header */

struct olsr_header_v4 {
  uint8_t type;
  uint8_t vtime;
  uint16_t size;
  uint32_t orig;
  uint8_t ttl;
  uint8_t hops;
  uint16_t seqno;
};

/* serialized IPv6 OLSR header */

struct olsr_header_v6 {
  uint8_t type;
  uint8_t vtime;
  uint16_t size;
  unsigned char orig[16];
  uint8_t ttl;
  uint8_t hops;
  uint16_t seqno;
};

/* deserialized LQ_HELLO */
//hello消息的头部部分
struct lq_hello_neighbor {
  uint8_t link_type;                /*
                                     *链路类型，有4种类型分别是 
                                     *UNSPEC_LINK 表示没有关于链路更多的信息
                                     *ASYM_LINK， 表示是一个非对称链路
                                     *SYM_LINK ，  表示是一个对称链路
                                     *LOST_LINK    表示链路已经丢失
                                     */  
  uint8_t neigh_type;
/*
*neigh _type 指的是邻居的类型，其取值有3个分别为：
*  SYM_NEIGH 表示该结点与发送结点至少有一条对称链路
*  MPR-NEIGH 表示该为SYM_NEIGH邻居外，还被发送方选择成为了MPR结点
*  NOT_NEIGH 表示结点不可能与发送结点成为对称结点
*/
  union olsr_ip_addr addr;
  struct lq_hello_neighbor *next;
  uint32_t linkquality[0];
};
//hello消息的数据包头部，即lq_hello_message是一个完整的数据包，里面有lq_hello_neighbor和lq_hello_neighbor信息
struct lq_hello_message {
  struct olsr_common comm;
  olsr_reltime htime;
  uint8_t will;
  struct lq_hello_neighbor *neigh;
};

/* serialized LQ_HELLO */
//lq_hello_header与lq_hello_neighbor共同组成hello消息首部
struct lq_hello_info_header {
  uint8_t link_code;
  uint8_t reserved; 
  uint16_t size;
};

struct lq_hello_header {
  uint16_t reserved;    //在这里reserved是一个定值 0000000000000
  uint8_t htime;         //表示该结点在这个接口发送hello包的间隔，有特定的计算公式
  uint8_t will;          /*衡量该结点愿意承担传输任务的积极性，WILL_NEVER表示该结点不会被结点选择为MPR结点
                                                                WILL_ALWAYS表示该节点必会被选择我MPR结点
                         */
};

/* deserialized LQ_TC */
struct lq_tc_message {
  struct olsr_common comm;
  union olsr_ip_addr from;
  uint16_t ansn;
  struct tc_mpr_addr *neigh;
};

/* serialized LQ_TC */

struct lq_tc_header {
  uint16_t ansn;
  uint8_t lower_border;
  uint8_t upper_border;
};

static INLINE void
pkt_get_u8(const uint8_t ** p, uint8_t * var)
{
  *var = *(const uint8_t *)(*p);
  *p += sizeof(uint8_t);
}
static INLINE void
pkt_get_u16(const uint8_t ** p, uint16_t * var)
{
  *var = ntohs(**((const uint16_t **)p));
  *p += sizeof(uint16_t);
}
static INLINE void
pkt_get_u32(const uint8_t ** p, uint32_t * var)
{
  *var = ntohl(**((const uint32_t **)p));
  *p += sizeof(uint32_t);
}
static INLINE void
pkt_get_s8(const uint8_t ** p, int8_t * var)
{
  *var = *(const int8_t *)(*p);
  *p += sizeof(int8_t);
}
static INLINE void
pkt_get_s16(const uint8_t ** p, int16_t * var)
{
  *var = ntohs(**((const int16_t **)p));
  *p += sizeof(int16_t);
}
static INLINE void
pkt_get_s32(const uint8_t ** p, int32_t * var)
{
  *var = ntohl(**((const int32_t **)p));
  *p += sizeof(int32_t);
}
static INLINE void
pkt_get_reltime(const uint8_t ** p, olsr_reltime * var)
{
  *var = me_to_reltime(**p);
  *p += sizeof(uint8_t);
}
static INLINE void
pkt_get_ipaddress(const uint8_t ** p, union olsr_ip_addr *var)
{
  memcpy(var, *p, olsr_cnf->ipsize);
  *p += olsr_cnf->ipsize;
}
static INLINE void
pkt_get_prefixlen(const uint8_t ** p, uint8_t * var)
{
  *var = netmask_to_prefix(*p, olsr_cnf->ipsize);
  *p += olsr_cnf->ipsize;
}

static INLINE void
pkt_ignore_u8(const uint8_t ** p)
{
  *p += sizeof(uint8_t);
}
static INLINE void
pkt_ignore_u16(const uint8_t ** p)
{
  *p += sizeof(uint16_t);
}
static INLINE void
pkt_ignore_u32(const uint8_t ** p)
{
  *p += sizeof(uint32_t);
}
static INLINE void
pkt_ignore_s8(const uint8_t ** p)
{
  *p += sizeof(int8_t);
}
static INLINE void
pkt_ignore_s16(const uint8_t ** p)
{
  *p += sizeof(int16_t);
}
static INLINE void
pkt_ignore_s32(const uint8_t ** p)
{
  *p += sizeof(int32_t);
}
static INLINE void
pkt_ignore_ipaddress(const uint8_t ** p)
{
  *p += olsr_cnf->ipsize;
}
static INLINE void
pkt_ignore_prefixlen(const uint8_t ** p)
{
  *p += olsr_cnf->ipsize;
}

static INLINE void
pkt_put_u8(uint8_t ** p, uint8_t var)
{
  **((uint8_t **)p) = var;
  *p += sizeof(uint8_t);
}
static INLINE void
pkt_put_u16(uint8_t ** p, uint16_t var)
{
  **((uint16_t **)p) = htons(var);
  *p += sizeof(uint16_t);
}
static INLINE void
pkt_put_u32(uint8_t ** p, uint32_t var)
{
  **((uint32_t **)p) = htonl(var);
  *p += sizeof(uint32_t);
}
static INLINE void
pkt_put_s8(uint8_t ** p, int8_t var)
{
  **((int8_t **)p) = var;
  *p += sizeof(int8_t);
}
static INLINE void
pkt_put_s16(uint8_t ** p, int16_t var)
{
  **((int16_t **)p) = htons(var);
  *p += sizeof(int16_t);
}
static INLINE void
pkt_put_s32(uint8_t ** p, int32_t var)
{
  **((int32_t **)p) = htonl(var);
  *p += sizeof(int32_t);
}
static INLINE void
pkt_put_reltime(uint8_t ** p, olsr_reltime var)
{
  **p = reltime_to_me(var);
  *p += sizeof(uint8_t);
}
static INLINE void
pkt_put_ipaddress(uint8_t ** p, const union olsr_ip_addr *var)
{
  memcpy(*p, var, olsr_cnf->ipsize);
  *p += olsr_cnf->ipsize;
}

void olsr_output_lq_hello(void *para);

void olsr_output_lq_tc(void *para);

void olsr_input_lq_hello(union olsr_message *ser, struct interface *inif, union olsr_ip_addr *from);

extern bool lq_tc_pending;

#endif

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

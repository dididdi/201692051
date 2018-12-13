
/*
 * The olsr.org Optimized Link-State Routing daemon(olsrd)
 * Copyright (c) 2004, Andreas Tonnesen(andreto@olsr.org)
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

/*
 * Link sensing database for the OLSR routing daemon
 */
/*
*link_set 是一个关于本地链路信息的信息表
*/
#ifndef _LINK_SET_H
#define _LINK_SET_H

#include "lq_plugin.h"
#include "packet.h"
#include "common/list.h"
#include "mantissa.h"

#define MID_ALIAS_HACK_VTIME  10.0

#define LINK_LOSS_MULTIPLIER (1<<16)

struct link_entry {
  union olsr_ip_addr local_iface_addr;//local节点的接口地址
  union olsr_ip_addr neighbor_iface_addr;//邻居节点的接口地址
  const struct interface *inter;
  char *if_name;
  struct timer_entry *link_timer;//记录到期的时间，必须被移除
  struct timer_entry *link_sym_timer;//当链路是对称状态时的时间
  uint32_t ASYM_time;//当邻居接口被认为已经是heard状态的时间
  /*
*当L_timer和L_sym_timer都到期的时候该条链路被认为丢失
*当L_timer没有过期的时候，链路状态声明为对称的，当过期后，声明为非对称的
*/
  olsr_reltime vtime;
  struct neighbor_entry *neighbor;//一个neighbor体的链表，用来存储当前路由器的邻居信息
  uint8_t prev_status;

  /*
   * Hysteresis
   */
  float L_link_quality;
  int L_link_pending;
  uint32_t L_LOST_LINK_time;
  struct timer_entry *link_hello_timer; /* When we should receive a new HELLO */
  olsr_reltime last_htime;
  bool olsr_seqno_valid;
  uint16_t olsr_seqno;

  /*
   * packet loss
   */
  olsr_reltime loss_helloint;
  struct timer_entry *link_loss_timer;

  /* user defined multiplies for link quality, multiplied with 65536 */
  uint32_t loss_link_multiplier;

  /* cost of this link */
  olsr_linkcost linkcost;

  struct list_node link_list;          /* double linked list of all link entries */
  uint32_t linkquality[0];
};

/* inline to recast from link_list back to link_entry */
LISTNODE2STRUCT(list2link, struct link_entry, link_list);

#define OLSR_LINK_JITTER       5        /* percent */
#define OLSR_LINK_HELLO_JITTER 0        /* percent jitter */
#define OLSR_LINK_SYM_JITTER   0        /* percent jitter */
#define OLSR_LINK_LOSS_JITTER  0        /* percent jitter */

/* deletion safe macro for link entry traversal */
#define OLSR_FOR_ALL_LINK_ENTRIES(link) \
{ \
  struct list_node *link_head_node, *link_node, *next_link_node; \
  link_head_node = &link_entry_head; \
  for (link_node = link_head_node->next; \
    link_node != link_head_node; link_node = next_link_node) { \
    next_link_node = link_node->next; \
    link = list2link(link_node);//对链表进行连接
#define OLSR_FOR_ALL_LINK_ENTRIES_END(link) }}
/*
*link_set 中的全局变量
link_entry_head链路链表的头部结点
link_changes 记录MPRs集合中是否有改变
*/
/* Externals */
extern struct list_node link_entry_head;
extern bool link_changes;

/* Function prototypes */

void olsr_set_link_timer(struct link_entry *, unsigned int);//设置链路到期的时间
void olsr_init_link_set(void);//初始化
void olsr_reset_all_links(void);//这个函数的功能是设置所有链路都为丢失状态，这样最后的一个Hello消息会告诉你的邻居你走了
void olsr_delete_link_entry_by_ip(const union olsr_ip_addr *);//删除所有的匹配Ip的链路信息
void olsr_expire_link_hello_timer(void *);
void signal_link_changes(bool);        /* XXX ugly */

struct link_entry *get_best_link_to_neighbor(const union olsr_ip_addr *);

struct link_entry *lookup_link_entry(const union olsr_ip_addr *, const union olsr_ip_addr *remote_main, const struct interface *);//查找一条链路

struct link_entry *update_link_entry(const union olsr_ip_addr *, const union olsr_ip_addr *, const struct hello_message *,
                                     const struct interface *);//更新一条链路

int check_neighbor_link(const union olsr_ip_addr *);
int replace_neighbor_link_set(const struct neighbor_entry *, struct neighbor_entry *);
int lookup_link_status(const struct link_entry *);
void olsr_update_packet_loss_hello_int(struct link_entry *, olsr_reltime);
void olsr_received_hello_handler(struct link_entry *entry);
void olsr_print_link_set(void);

#endif

/*
 * Local Variables:
 * c-basic-offset: 2
 * indent-tabs-mode: nil
 * End:
 */

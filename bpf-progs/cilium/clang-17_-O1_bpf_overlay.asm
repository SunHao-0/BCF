0000000000000000 <tail_handle_ipv6>:
; {
       0:	r6 = r1
; 	return ctx->cb[off];
       1:	w1 = *(u32 *)(r6 + 0x30)
       2:	*(u32 *)(r10 - 0x90) = w1
       3:	w7 = 0x0
; 	ctx->cb[off] = data;
       4:	*(u32 *)(r6 + 0x30) = w7
; 		ctx_pull_data(ctx, (__u32)tot_len);
       5:	r1 = r6
       6:	w2 = 0x28
       7:	call 0x27
; DEFINE_FUNC_CTX_POINTER(data_end)
       8:	w1 = *(u32 *)(r6 + 0x50)
; DEFINE_FUNC_CTX_POINTER(data)
       9:	w0 = *(u32 *)(r6 + 0x4c)
      10:	w9 = -0x86
; 	if (data + tot_len > data_end)
      11:	r2 = r0
      12:	r2 += 0x28
; 	if (!revalidate_data_pull(ctx, &data, &data_end, &ip6))
      13:	if r2 > r1 goto +0x3c8 <LBB16_296>
; 	volatile __u32 tc_index = ctx->tc_index;
      14:	w1 = *(u32 *)(r6 + 0x2c)
      15:	*(u32 *)(r10 - 0x48) = w1
; 	ctx->tc_index &= ~TC_INDEX_F_SKIP_NODEPORT;
      16:	w1 &= -0x5
      17:	*(u32 *)(r6 + 0x2c) = w1
; 	return tc_index & TC_INDEX_F_SKIP_NODEPORT;
      18:	w1 = *(u32 *)(r10 - 0x48)
      19:	w1 &= 0x4
; 	if (!ctx_skip_nodeport(ctx)) {
      20:	if w1 != 0x0 goto +0x140 <LBB16_247>
      21:	*(u64 *)(r10 - 0x98) = r6
      22:	w1 = 0x0
; 	struct ipv6_ct_tuple tuple __align_stack_8 = {};
      23:	*(u16 *)(r10 - 0x4c) = w1
      24:	*(u32 *)(r10 - 0x50) = w1
      25:	r1 = 0x0
      26:	*(u64 *)(r10 - 0x58) = r1
      27:	*(u64 *)(r10 - 0x60) = r1
      28:	*(u64 *)(r10 - 0x68) = r1
      29:	*(u64 *)(r10 - 0x70) = r1
; 	struct lb6_key key = {};
      30:	*(u64 *)(r10 - 0x78) = r1
      31:	*(u64 *)(r10 - 0x80) = r1
      32:	*(u64 *)(r10 - 0x88) = r1
; 	tuple->nexthdr = ip6->nexthdr;
      33:	w9 = *(u8 *)(r0 + 0x6)
      34:	*(u8 *)(r10 - 0x4c) = w9
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
      35:	r1 = *(u64 *)(r0 + 0x20)
      36:	*(u64 *)(r10 - 0x68) = r1
; 	case  8: jmp_8:  __it_mob(d, s, 64);
      37:	r1 = *(u64 *)(r0 + 0x18)
      38:	*(u64 *)(r10 - 0x70) = r1
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
      39:	r1 = *(u64 *)(r0 + 0x10)
      40:	*(u64 *)(r10 - 0x58) = r1
      41:	*(u64 *)(r10 - 0xa8) = r0
; 	case  8: jmp_8:  __it_mob(d, s, 64);
      42:	r1 = *(u64 *)(r0 + 0x8)
      43:	*(u64 *)(r10 - 0x60) = r1
      44:	w2 = 0x28
; 		switch (nh) {
      45:	if w9 > 0x3c goto +0x5a <LBB16_29>
      46:	r1 = 0x1
      47:	r1 <<= r9
      48:	r3 = 0x1008080000000001 ll
      50:	r1 &= r3
      51:	if r1 != 0x0 goto +0x4 <LBB16_6>
      52:	if r9 == 0x2c goto +0x56 <LBB16_30>
      53:	w7 = -0x9c
      54:	if r9 == 0x3b goto +0x55 <LBB16_31>
      55:	goto +0x50 <LBB16_29>

00000000000001c0 <LBB16_6>:
      56:	r3 = r10
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      57:	r3 += -0x48
      58:	w6 = 0x2
      59:	r1 = *(u64 *)(r10 - 0x98)
      60:	w4 = 0x2
      61:	call 0x1a
      62:	w7 = -0x86
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      63:	if w0 s< 0x0 goto +0x4c <LBB16_31>
; 			if (nh == NEXTHDR_AUTH)
      64:	if w9 == 0x33 goto +0x1 <LBB16_9>
      65:	w6 = 0x3

0000000000000210 <LBB16_9>:
      66:	w8 = *(u8 *)(r10 - 0x47)
; 			if (nh == NEXTHDR_AUTH)
      67:	w8 <<= w6
      68:	w2 = w8
      69:	w2 += 0x30
      70:	w9 = *(u8 *)(r10 - 0x48)
; 		switch (nh) {
      71:	if w9 > 0x3c goto +0x40 <LBB16_29>
      72:	r1 = 0x1
      73:	r1 <<= r9
      74:	r3 = 0x1008080000000001 ll
      76:	r1 &= r3
      77:	if r1 != 0x0 goto +0x4 <LBB16_13>
      78:	if r9 == 0x2c goto +0x3c <LBB16_30>
      79:	w7 = -0x9c
      80:	if r9 == 0x3b goto +0x3b <LBB16_31>
      81:	goto +0x36 <LBB16_29>

0000000000000290 <LBB16_13>:
      82:	r3 = r10
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
      83:	r3 += -0x48
      84:	w6 = 0x2
      85:	r1 = *(u64 *)(r10 - 0x98)
      86:	w4 = 0x2
      87:	call 0x1a
      88:	if w0 s< 0x0 goto +0x33 <LBB16_31>
; 			if (nh == NEXTHDR_AUTH)
      89:	if w9 == 0x33 goto +0x1 <LBB16_16>
      90:	w6 = 0x3

00000000000002d8 <LBB16_16>:
      91:	w1 = *(u8 *)(r10 - 0x47)
; 			if (nh == NEXTHDR_AUTH)
      92:	w1 <<= w6
      93:	w8 += w1
      94:	w8 += 0x38
      95:	w9 = *(u8 *)(r10 - 0x48)
      96:	w2 = w8
; 		switch (nh) {
      97:	if w9 > 0x3c goto +0x26 <LBB16_29>
      98:	r1 = 0x1
      99:	r1 <<= r9
     100:	r2 = 0x1008080000000001 ll
     102:	r1 &= r2
     103:	if r1 != 0x0 goto +0x5 <LBB16_20>
     104:	if r9 == 0x2c goto +0x22 <LBB16_30>
     105:	w2 = w8
     106:	w7 = -0x9c
     107:	if r9 == 0x3b goto +0x20 <LBB16_31>
     108:	goto +0x1b <LBB16_29>

0000000000000368 <LBB16_20>:
     109:	r3 = r10
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
     110:	r3 += -0x48
     111:	w6 = 0x2
     112:	r1 = *(u64 *)(r10 - 0x98)
     113:	w2 = w8
     114:	w4 = 0x2
     115:	call 0x1a
     116:	if w0 s< 0x0 goto +0x17 <LBB16_31>
; 			if (nh == NEXTHDR_AUTH)
     117:	if w9 == 0x33 goto +0x1 <LBB16_23>
     118:	w6 = 0x3

00000000000003b8 <LBB16_23>:
     119:	w1 = *(u8 *)(r10 - 0x47)
; 			if (nh == NEXTHDR_AUTH)
     120:	w1 <<= w6
     121:	w8 += w1
     122:	w8 += 0x8
     123:	w9 = *(u8 *)(r10 - 0x48)
     124:	w2 = w8
; 		switch (nh) {
     125:	if w9 > 0x3c goto +0xa <LBB16_29>
     126:	r1 = 0x1
     127:	r1 <<= r9
     128:	r2 = 0x1008080000000001 ll
     130:	r1 &= r2
     131:	if r1 != 0x0 goto +0x381 <LBB16_27>
     132:	if r9 == 0x2c goto +0x6 <LBB16_30>
     133:	w2 = w8
     134:	w7 = -0x9c
     135:	if r9 == 0x3b goto +0x4 <LBB16_31>

0000000000000440 <LBB16_29>:
; 			*nexthdr = nh;
     136:	*(u8 *)(r10 - 0x4c) = w9
     137:	w7 = w2
     138:	goto +0x1 <LBB16_31>

0000000000000458 <LBB16_30>:
     139:	w7 = -0x9d

0000000000000460 <LBB16_31>:
     140:	w8 = -0x1
     141:	w9 = w7
     142:	r6 = *(u64 *)(r10 - 0x98)
; 	if (ret < 0) {
     143:	if w7 s< 0x0 goto +0x12 <LBB16_38>
; 	switch (tuple->nexthdr) {
     144:	w1 = *(u8 *)(r10 - 0x4c)
     145:	if w1 == 0x6 goto +0x4 <LBB16_35>
     146:	w9 = -0x9f
     147:	w8 = w7
; 	switch (tuple->nexthdr) {
     148:	if w1 == 0x3a goto +0xd <LBB16_38>
     149:	if w1 != 0x11 goto +0xa <LBB16_36>

00000000000004b0 <LBB16_35>:
; 		if (l4_load_ports(ctx, *l4_off, &tuple->dport) < 0)
     150:	r3 = r10
     151:	r3 += -0x50
; 	return ctx_load_bytes(ctx, off, ports, 2 * sizeof(__be16));
     152:	r1 = r6
     153:	w2 = w7
     154:	w4 = 0x4
     155:	call 0x1a
     156:	w9 = w0
     157:	w9 s>>= 0x1f
     158:	w9 &= -0x87
     159:	goto +0x1 <LBB16_37>

0000000000000500 <LBB16_36>:
     160:	w9 = -0x8e

0000000000000508 <LBB16_37>:
     161:	w8 = w7

0000000000000510 <LBB16_38>:
; 	if (IS_ERR(ret)) {
     162:	if w9 s> -0x1 goto +0x7 <LBB16_42>
; 		if (ret == DROP_UNSUPP_SERVICE_PROTO) {
     163:	if w9 == -0x9f goto +0xa0 <LBB16_243>
     164:	w1 = 0x0
; 		if (ret == DROP_UNSUPP_SERVICE_PROTO) {
     165:	*(u32 *)(r10 - 0xa0) = w1
     166:	if w9 != -0x8e goto +0xa9 <LBB16_245>
     167:	*(u32 *)(r10 - 0xa0) = w1
     168:	w9 = 0x0
     169:	goto +0xa6 <LBB16_245>

0000000000000550 <LBB16_42>:
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
     170:	r1 = *(u64 *)(r10 - 0x68)
     171:	*(u64 *)(r10 - 0x80) = r1
; 	case  8: jmp_8:  __it_mob(d, s, 64);
     172:	r1 = *(u64 *)(r10 - 0x70)
     173:	*(u64 *)(r10 - 0x88) = r1
; 	key->dport = tuple->sport;
     174:	w1 = *(u16 *)(r10 - 0x4e)
     175:	*(u16 *)(r10 - 0x78) = w1
     176:	w1 = 0x0
; 	key->scope = LB_LOOKUP_SCOPE_EXT;
     177:	*(u8 *)(r10 - 0x73) = w1
; 	key->backend_slot = 0;
     178:	*(u16 *)(r10 - 0x76) = w1
     179:	r2 = r10
     180:	r2 += -0x88
; 	svc = map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
     181:	r1 = 0x0 ll
     183:	call 0x1
     184:	r7 = r0
; 	if (svc) {
     185:	if r7 == 0x0 goto +0x8a <LBB16_243>
     186:	*(u32 *)(r10 - 0xb0) = w8
; 	return svc->flags & SVC_FLAG_SOURCE_RANGE;
     187:	w1 = *(u8 *)(r7 + 0x8)
     188:	w1 <<= 0x18
     189:	w1 s>>= 0x18
; 	if (!lb6_svc_has_src_range_check(svc))
     190:	if w1 s> -0x1 goto +0x45 <LBB16_47>
     191:	r1 = *(u64 *)(r10 - 0xa8)
     192:	r1 += 0x8
; 		.rev_nat_id = svc->rev_nat_index,
     193:	w2 = *(u16 *)(r7 + 0x6)
; 	key = (typeof(key)) {
     194:	*(u16 *)(r10 - 0x44) = w2
     195:	w2 = 0xa0
     196:	*(u32 *)(r10 - 0x48) = w2
     197:	w2 = 0x0
     198:	w3 = 0x0
; 	key = (typeof(key)) {
     199:	*(u32 *)(r10 - 0xa0) = w3
     200:	*(u16 *)(r10 - 0x42) = w2
     201:	w3 = *(u8 *)(r1 + 0x1)
     202:	w3 <<= 0x8
     203:	w2 = *(u8 *)(r1 + 0x0)
     204:	w3 |= w2
     205:	w4 = *(u8 *)(r1 + 0x2)
     206:	w4 <<= 0x10
     207:	w2 = *(u8 *)(r1 + 0x3)
     208:	w2 <<= 0x18
     209:	w2 |= w4
     210:	w5 = *(u8 *)(r1 + 0xd)
     211:	w5 <<= 0x8
     212:	w4 = *(u8 *)(r1 + 0xc)
     213:	w5 |= w4
     214:	w0 = *(u8 *)(r1 + 0xe)
     215:	w0 <<= 0x10
     216:	w4 = *(u8 *)(r1 + 0xf)
     217:	w4 <<= 0x18
     218:	w4 |= w0
     219:	w4 |= w5
     220:	w2 |= w3
     221:	w3 = *(u8 *)(r1 + 0x5)
     222:	w3 <<= 0x8
     223:	w5 = *(u8 *)(r1 + 0x4)
     224:	w3 |= w5
     225:	w5 = *(u8 *)(r1 + 0x6)
     226:	w5 <<= 0x10
     227:	w0 = *(u8 *)(r1 + 0x7)
     228:	w0 <<= 0x18
     229:	w0 |= w5
     230:	w0 |= w3
     231:	*(u32 *)(r10 - 0x3c) = w0
     232:	*(u32 *)(r10 - 0x40) = w2
     233:	*(u32 *)(r10 - 0x34) = w4
     234:	w2 = *(u8 *)(r1 + 0x9)
     235:	w2 <<= 0x8
     236:	w3 = *(u8 *)(r1 + 0x8)
     237:	w2 |= w3
     238:	w3 = *(u8 *)(r1 + 0xa)
     239:	w3 <<= 0x10
     240:	w1 = *(u8 *)(r1 + 0xb)
     241:	w1 <<= 0x18
     242:	w1 |= w3
     243:	w1 |= w2
     244:	*(u32 *)(r10 - 0x38) = w1
     245:	r2 = r10
     246:	r2 += -0x48
; 	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
     247:	r1 = 0x0 ll
     249:	call 0x1
     250:	w1 = 0x1
; 	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
     251:	if r0 != 0x0 goto +0x1 <LBB16_46>
     252:	w1 = 0x0

00000000000007e8 <LBB16_46>:
; 	return verdict ^ !!(svc->flags2 & SVC_FLAG_SOURCE_RANGE_DENY);
     253:	w2 = *(u8 *)(r7 + 0x9)
     254:	w2 >>= 0x6
     255:	w1 ^= w2
     256:	w9 = -0xb1
; 	if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
     257:	w1 &= 0x1
     258:	if w1 != 0x0 goto +0x1 <LBB16_47>
     259:	goto +0x4c <LBB16_245>

0000000000000820 <LBB16_47>:
     260:	w9 = -0xae
     261:	w1 = 0x0
; 	return __lb_svc_is_routable(svc->flags);
     262:	*(u32 *)(r10 - 0xa0) = w1
     263:	w1 = *(u8 *)(r7 + 0x8)
; 	return (flags & SVC_FLAG_ROUTABLE) != 0;
     264:	w1 &= 0x40
; 	if (!lb6_svc_is_routable(svc))
     265:	if w1 == 0x0 goto +0x46 <LBB16_245>
; 	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
     266:	w1 = *(u8 *)(r7 + 0x9)
     267:	w1 &= 0x4
; 	if (lb6_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
     268:	if w1 == 0x0 goto +0x121 <LBB16_61>
     269:	w1 = *(u32 *)(r7 + 0x0)
     270:	if w1 == 0x0 goto +0x11f <LBB16_61>
; 				  THIS_INTERFACE_IFINDEX, TRACE_REASON_POLICY, monitor);
     271:	r2 = 0x0 ll
     273:	w2 = *(u32 *)(r2 + 0x0)
     274:	r2 = 0x568803a772ce ll
; 	union macaddr host_mac = HOST_IFINDEX_MAC;
     276:	*(u64 *)(r10 - 0x48) = r2
; 	union macaddr router_mac = THIS_INTERFACE_MAC;
     277:	r2 = 0x0 ll
     279:	w2 = *(u32 *)(r2 + 0x0)
     280:	*(u32 *)(r10 - 0x10) = w2
     281:	r2 = 0x0 ll
     283:	w2 = *(u32 *)(r2 + 0x0)
     284:	*(u16 *)(r10 - 0xc) = w2
; 		       MARK_MAGIC_TO_PROXY | (proxy_port << 16));
     285:	w1 <<= 0x10
     286:	w1 |= 0x200
; 	ctx->cb[off] = data;
     287:	*(u32 *)(r6 + 0x30) = w1
     288:	r3 = r10
     289:	r3 += -0x49
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     290:	r1 = r6
     291:	w2 = 0x7
     292:	w4 = 0x1
     293:	call 0x1a
     294:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     295:	if w0 s< 0x0 goto +0xf <LBB16_53>
     296:	w9 = -0xc4
; 	if (hl <= 1)
     297:	w1 = *(u8 *)(r10 - 0x49)
     298:	if w1 < 0x2 goto +0xc <LBB16_53>
; 	hl--;
     299:	w1 += -0x1
     300:	*(u8 *)(r10 - 0x49) = w1
     301:	r3 = r10
     302:	r3 += -0x49
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     303:	r1 = r6
     304:	w2 = 0x7
     305:	w4 = 0x1
     306:	w5 = 0x1
     307:	call 0x9
     308:	w9 = w0
     309:	w9 s>>= 0x1f
     310:	w9 &= -0x8d

00000000000009b8 <LBB16_53>:
; 	if (IS_ERR(ret)) {
     311:	if w9 s> -0x1 goto +0x198 <LBB16_56>
; 		if (ret == DROP_TTL_EXCEEDED)
     312:	if w9 != -0xc4 goto +0x1a9 <LBB16_59>
     313:	w1 = 0x2
; 	ctx->cb[off] = data;
     314:	*(u32 *)(r6 + 0x34) = w1
     315:	w1 = 0x0
     316:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     317:	r1 = r6
     318:	r2 = 0x0 ll
     320:	r3 = 0x5
     321:	call 0xc
     322:	w9 = -0x8c
     323:	goto +0x19e <LBB16_59>

0000000000000a20 <LBB16_243>:
; 	ctx->cb[off] = data;
     324:	w1 = *(u32 *)(r10 - 0x90)
     325:	*(u32 *)(r6 + 0x30) = w1
     326:	w1 = 0x0
; 	ctx->cb[off] = data;
     327:	*(u32 *)(r6 + 0x34) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     328:	r1 = r6
     329:	r2 = 0x0 ll
     331:	r3 = 0x25
     332:	call 0xc
     333:	w9 = -0x8c
     334:	w1 = 0x25

0000000000000a78 <LBB16_244>:
     335:	*(u32 *)(r10 - 0xa0) = w1

0000000000000a80 <LBB16_245>:
     336:	r0 = *(u64 *)(r10 - 0xa8)
     337:	w7 = *(u32 *)(r10 - 0xa0)
; 		if (ret < 0 || ret == TC_ACT_REDIRECT)
     338:	if w9 s< 0x0 goto +0x283 <LBB16_296>
     339:	w8 = w9
; 		if (ret < 0 || ret == TC_ACT_REDIRECT)
     340:	if w9 == 0x7 goto +0x281 <LBB16_296>

0000000000000aa8 <LBB16_247>:
; DEFINE_FUNC_CTX_POINTER(data_end)
     341:	w1 = *(u32 *)(r6 + 0x50)
; DEFINE_FUNC_CTX_POINTER(data)
     342:	w3 = *(u32 *)(r6 + 0x4c)
; 	if (data + tot_len > data_end)
     343:	r2 = r3
     344:	r2 += 0x28
     345:	if r2 > r1 goto +0x1 <LBB16_249>
     346:	r0 = r3

0000000000000ad8 <LBB16_249>:
     347:	w9 = -0x86
; 	if (!revalidate_data(ctx, &data, &data_end, &ip6))
     348:	if r2 > r1 goto +0x279 <LBB16_296>
     349:	*(u32 *)(r10 - 0xa0) = w7
     350:	w1 = 0x2000000
; 	struct ipcache_key key = {
     351:	*(u32 *)(r10 - 0x44) = w1
     352:	w1 = 0xa0
; 		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
     353:	*(u32 *)(r10 - 0x48) = w1
; 		.ip6 = *addr,
     354:	w1 = *(u8 *)(r0 + 0xd)
     355:	w1 <<= 0x8
     356:	w2 = *(u8 *)(r0 + 0xc)
     357:	w1 |= w2
     358:	w3 = *(u8 *)(r0 + 0xe)
     359:	w3 <<= 0x10
     360:	w2 = *(u8 *)(r0 + 0xf)
     361:	w2 <<= 0x18
     362:	w2 |= w3
     363:	w4 = *(u8 *)(r0 + 0x9)
     364:	w4 <<= 0x8
     365:	w3 = *(u8 *)(r0 + 0x8)
     366:	w4 |= w3
     367:	w5 = *(u8 *)(r0 + 0xa)
     368:	w5 <<= 0x10
     369:	w3 = *(u8 *)(r0 + 0xb)
     370:	w3 <<= 0x18
     371:	w3 |= w5
     372:	w5 = *(u8 *)(r0 + 0x15)
     373:	w5 <<= 0x8
     374:	r7 = r0
     375:	w0 = *(u8 *)(r7 + 0x14)
     376:	w5 |= w0
     377:	w0 = *(u8 *)(r7 + 0x16)
     378:	w0 <<= 0x10
     379:	*(u64 *)(r10 - 0x98) = r6
     380:	w6 = *(u8 *)(r7 + 0x17)
     381:	w6 <<= 0x18
     382:	w6 |= w0
     383:	w6 |= w5
     384:	w3 |= w4
     385:	w2 |= w1
     386:	w1 = *(u8 *)(r7 + 0x13)
     387:	w4 = *(u8 *)(r7 + 0x12)
     388:	w5 = *(u8 *)(r7 + 0x10)
     389:	*(u64 *)(r10 - 0xa8) = r7
     390:	w0 = *(u8 *)(r7 + 0x11)
     391:	w7 = 0x0
; 	key.cluster_id = (__u16)cluster_id;
     392:	*(u16 *)(r10 - 0x44) = w7
; 		.ip6 = *addr,
     393:	*(u32 *)(r10 - 0x3c) = w2
     394:	*(u32 *)(r10 - 0x40) = w3
     395:	*(u32 *)(r10 - 0x34) = w6
     396:	r6 = *(u64 *)(r10 - 0x98)
     397:	w0 <<= 0x8
     398:	w0 |= w5
     399:	w4 <<= 0x10
     400:	w1 <<= 0x18
     401:	w1 |= w4
     402:	w1 |= w0
     403:	*(u32 *)(r10 - 0x38) = w1
     404:	r2 = r10
     405:	r2 += -0x48
; 	return map_lookup_elem(map, &key);
     406:	r1 = 0x0 ll
     408:	call 0x1
; 	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
     409:	w1 = *(u32 *)(r6 + 0x8)
     410:	w1 &= 0xf00
; 	if (decrypted) {
     411:	if w1 != 0xd00 goto +0x2 <LBB16_252>
; 		if (info)
     412:	if r0 == 0x0 goto +0xb <LBB16_257>
     413:	goto +0x8 <LBB16_256>

0000000000000cf0 <LBB16_252>:
; 		if (info && (identity_is_remote_node(*identity) ||
     414:	if r0 == 0x0 goto +0x9 <LBB16_257>
     415:	w2 = *(u32 *)(r10 - 0x90)
     416:	w2 &= -0x1000000
; 	return identity == REMOTE_NODE_ID ||
     417:	if w2 == 0x2000000 goto +0x4 <LBB16_256>
     418:	w2 = *(u32 *)(r10 - 0x90)
     419:	if w2 == 0x7 goto +0x2 <LBB16_256>
     420:	w2 = *(u32 *)(r10 - 0x90)
     421:	if w2 != 0x6 goto +0x2 <LBB16_257>

0000000000000d30 <LBB16_256>:
     422:	w2 = *(u32 *)(r0 + 0x0)
     423:	*(u32 *)(r10 - 0x90) = w2

0000000000000d40 <LBB16_257>:
; 	if (!decrypted) {
     424:	if w1 == 0xd00 goto +0x20 <LBB16_270>
     425:	r1 = *(u64 *)(r10 - 0xa8)
; 		if (ip6->nexthdr != IPPROTO_ESP) {
     426:	w2 = *(u8 *)(r1 + 0x6)
     427:	*(u32 *)(r10 - 0xb0) = w2
     428:	if w2 == 0x32 goto +0x20 <LBB16_262>
; 	return ctx->len;
     429:	w7 = *(u32 *)(r6 + 0x0)
     430:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
     431:	*(u64 *)(r10 - 0x40) = r1
     432:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
     433:	*(u64 *)(r10 - 0x70) = r1
     434:	w1 = 0x3
; 	key.reason = reason;
     435:	*(u8 *)(r10 - 0x70) = w1
; 	key.file   = file;
     436:	*(u8 *)(r10 - 0x6c) = w1
     437:	w1 = 0x77
; 	key.line   = line;
     438:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
     439:	w1 = *(u8 *)(r10 - 0x6f)
     440:	w1 &= 0xfc
     441:	w1 |= 0x1
     442:	*(u8 *)(r10 - 0x6f) = w1
     443:	r2 = r10
     444:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
     445:	r1 = 0x0 ll
     447:	call 0x1
; 	if (entry) {
     448:	if r0 == 0x0 goto +0x127 <LBB16_261>
; 		entry->count += 1;
     449:	r1 = *(u64 *)(r0 + 0x0)
     450:	r1 += 0x1
     451:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
     452:	r1 = *(u64 *)(r0 + 0x8)
     453:	r1 += r7
     454:	*(u64 *)(r0 + 0x8) = r1
     455:	w9 = w8
     456:	goto +0x139 <LBB16_269>

0000000000000e48 <LBB16_270>:
     457:	w1 = 0x0
; 	ctx->mark = 0;
     458:	*(u32 *)(r6 + 0x8) = w1
     459:	r8 = *(u64 *)(r10 - 0xa8)
     460:	goto +0x139 <LBB16_271>

0000000000000e68 <LBB16_262>:
     461:	r1 += 0x8
     462:	r2 = 0x0
; 	struct node_key node_ip = {};
     463:	*(u64 *)(r10 - 0x48) = r2
     464:	*(u64 *)(r10 - 0x40) = r2
     465:	w2 = 0x2
; 	node_ip.family = ENDPOINT_KEY_IPV6;
     466:	*(u8 *)(r10 - 0x45) = w2
; 	struct node_key node_ip = {};
     467:	*(u32 *)(r10 - 0x38) = w7
; 	node_ip.ip6 = *ip6;
     468:	w3 = *(u8 *)(r1 + 0x5)
     469:	w3 <<= 0x8
     470:	w2 = *(u8 *)(r1 + 0x4)
     471:	w3 |= w2
     472:	w4 = *(u8 *)(r1 + 0x6)
     473:	w4 <<= 0x10
     474:	w2 = *(u8 *)(r1 + 0x7)
     475:	w2 <<= 0x18
     476:	w2 |= w4
     477:	w5 = *(u8 *)(r1 + 0x9)
     478:	w5 <<= 0x8
     479:	w4 = *(u8 *)(r1 + 0x8)
     480:	w5 |= w4
     481:	w0 = *(u8 *)(r1 + 0xa)
     482:	w0 <<= 0x10
     483:	w4 = *(u8 *)(r1 + 0xb)
     484:	w4 <<= 0x18
     485:	w4 |= w0
     486:	w4 |= w5
     487:	w2 |= w3
     488:	w3 = *(u8 *)(r1 + 0x1)
     489:	w3 <<= 0x8
     490:	w5 = *(u8 *)(r1 + 0x0)
     491:	w3 |= w5
     492:	w5 = *(u8 *)(r1 + 0x2)
     493:	w5 <<= 0x10
     494:	w0 = *(u8 *)(r1 + 0x3)
     495:	w0 <<= 0x18
     496:	w0 |= w5
     497:	w0 |= w3
     498:	*(u32 *)(r10 - 0x44) = w0
     499:	*(u32 *)(r10 - 0x40) = w2
     500:	*(u32 *)(r10 - 0x3c) = w4
     501:	w2 = *(u8 *)(r1 + 0xd)
     502:	w2 <<= 0x8
     503:	w3 = *(u8 *)(r1 + 0xc)
     504:	w2 |= w3
     505:	w3 = *(u8 *)(r1 + 0xe)
     506:	w3 <<= 0x10
     507:	w1 = *(u8 *)(r1 + 0xf)
     508:	w1 <<= 0x18
     509:	w1 |= w3
     510:	w1 |= w2
     511:	*(u32 *)(r10 - 0x38) = w1
     512:	r2 = r10
     513:	r2 += -0x48
; 	node_value = map_lookup_elem(&NODE_MAP_V2, &node_ip);
     514:	r1 = 0x0 ll
     516:	call 0x1
; 	if (!node_value)
     517:	if r0 == 0x0 goto +0x1 <LBB16_264>
; 	if (!node_value->id)
     518:	w7 = *(u16 *)(r0 + 0x0)

0000000000001038 <LBB16_264>:
     519:	w9 = -0xc5
; 		if (!node_id)
     520:	w1 = w7
     521:	w1 &= 0xffff
     522:	if w1 == 0x0 goto +0xf7 <LBB16_269>
; 	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
     523:	w7 <<= 0x10
     524:	w7 |= 0xd00
     525:	*(u32 *)(r6 + 0x8) = w7
     526:	r7 = r6
     527:	w6 = 0x0
; 		ctx_change_type(ctx, PACKET_HOST);
     528:	r1 = r7
     529:	w2 = 0x0
     530:	call 0x20
; 	return ctx->len;
     531:	w7 = *(u32 *)(r7 + 0x0)
     532:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
     533:	*(u64 *)(r10 - 0x40) = r1
     534:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
     535:	*(u64 *)(r10 - 0x70) = r1
; 	key.reason = reason;
     536:	*(u8 *)(r10 - 0x70) = w6
     537:	w1 = 0x6f
; 	key.file   = file;
     538:	*(u8 *)(r10 - 0x6c) = w1
     539:	w1 = 0x151
; 	key.line   = line;
     540:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
     541:	w1 = *(u8 *)(r10 - 0x6f)
     542:	w1 &= 0xfc
     543:	w1 |= 0x2
     544:	*(u8 *)(r10 - 0x6f) = w1
     545:	r2 = r10
     546:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
     547:	r1 = 0x0 ll
     549:	call 0x1
; 	if (entry) {
     550:	if r0 == 0x0 goto +0xce <LBB16_267>
; 		entry->count += 1;
     551:	r1 = *(u64 *)(r0 + 0x0)
     552:	r1 += 0x1
     553:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
     554:	r1 = *(u64 *)(r0 + 0x8)
     555:	r1 += r7
     556:	*(u64 *)(r0 + 0x8) = r1
     557:	goto +0xd2 <LBB16_268>

0000000000001170 <LBB16_61>:
     558:	*(u64 *)(r10 - 0xb8) = r7
; 	state->rev_nat_index = svc->rev_nat_index;
     559:	w1 = *(u16 *)(r7 + 0x6)
; 	__u8 flags = tuple->flags;
     560:	*(u32 *)(r10 - 0xc0) = w1
     561:	w1 = *(u8 *)(r10 - 0x4b)
     562:	*(u32 *)(r10 - 0xc8) = w1
     563:	w1 = 0x4
; 	tuple->flags = ct_lookup_select_tuple_type(dir, scope);
     564:	*(u8 *)(r10 - 0x4b) = w1
     565:	r3 = 0x0 ll
; 	if (tuple->nexthdr == IPPROTO_TCP)
     567:	w2 = *(u8 *)(r10 - 0x4c)
     568:	if w2 == 0x6 goto +0x2 <LBB16_63>
     569:	r3 = 0x0 ll

00000000000011d8 <LBB16_63>:
; 	case  8: jmp_8:  __it_mob(d, s, 64);
     571:	r1 = *(u64 *)(r10 - 0x60)
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
     572:	*(u64 *)(r10 - 0xe0) = r1
     573:	r1 = *(u64 *)(r10 - 0x58)
     574:	*(u64 *)(r10 - 0xe8) = r1
     575:	w8 = 0x0
; 	union tcp_flags tcp_flags = { .value = 0 };
     576:	*(u32 *)(r10 - 0x48) = w8
     577:	w9 = 0x0
     578:	*(u32 *)(r10 - 0xf0) = w2
; 	if (is_tcp) {
     579:	*(u64 *)(r10 - 0xd0) = r3
     580:	if w2 != 0x6 goto +0x13 <LBB16_68>
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
     581:	w2 = *(u32 *)(r10 - 0xb0)
     582:	w2 += 0xc
     583:	r3 = r10
     584:	r3 += -0x48
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
     585:	r1 = r6
     586:	w4 = 0x2
     587:	call 0x1a
     588:	w1 = -0x87
     589:	w7 = 0x0
     590:	w5 = 0x0
; 		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
     591:	if w0 s< 0x0 goto +0x1e8 <LBB16_99>
; 		action = ct_tcp_select_action(tcp_flags);
     592:	w9 = *(u32 *)(r10 - 0x48)
; 	if (unlikely(flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
     593:	w1 = w9
     594:	w1 &= 0x500
     595:	w9 >>= 0x9
     596:	w9 &= 0x1
     597:	if w1 == 0x0 goto +0x1 <LBB16_67>
     598:	w9 = 0x2

00000000000012b8 <LBB16_67>:
     599:	r3 = *(u64 *)(r10 - 0xd0)

00000000000012c0 <LBB16_68>:
; 		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_entry_types,
     600:	w1 = *(u32 *)(r10 - 0x48)
; 	entry = map_lookup_elem(map, tuple);
     601:	*(u32 *)(r10 - 0xd8) = w1
     602:	r2 = r10
     603:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
     604:	r1 = r3
     605:	call 0x1
     606:	r7 = r0
     607:	w1 = 0x1
     608:	*(u32 *)(r10 - 0xa0) = w1
     609:	w5 = 0x0
     610:	w1 = 0x0
; 	if (entry) {
     611:	if r7 == 0x0 goto +0x1ca <LBB16_95>
; 	    entry->rev_nat_index == state->rev_nat_index)
     612:	w1 = *(u32 *)(r10 - 0xc0)
     613:	r2 = r1
     614:	w3 = *(u16 *)(r7 + 0x26)
     615:	w5 = 0x0
     616:	w1 = 0x0
; 	if ((ct_entry_types & CT_ENTRY_SVC) &&
     617:	if w3 != w2 goto +0x1c4 <LBB16_95>
     618:	w1 = *(u32 *)(r10 - 0xd8)
     619:	w1 &= 0x200
     620:	*(u32 *)(r10 - 0xf8) = w1
; 		if (dir == CT_SERVICE && syn &&
     621:	if w1 == 0x0 goto +0xa <LBB16_73>
; 	return entry->tx_closing || entry->rx_closing;
     622:	w1 = *(u16 *)(r7 + 0x24)
     623:	w1 &= 0x3
; 		    ct_entry_closing(entry) &&
     624:	if w1 == 0x0 goto +0x7 <LBB16_73>
; 	return READ_ONCE(entry->last_tx_report) + wait_time <= bpf_mono_now();
     625:	w6 = *(u32 *)(r7 + 0x30)
     626:	w6 += 0x1e
     627:	call 0x5
     628:	r0 /= 0x3b9aca00
     629:	w5 = 0x0
     630:	w1 = 0x0
; 		if (dir == CT_SERVICE && syn &&
     631:	if r0 >= r6 goto +0x1b6 <LBB16_95>

00000000000013c0 <LBB16_73>:
; 	return !entry->rx_closing || !entry->tx_closing;
     632:	w1 = *(u16 *)(r7 + 0x24)
     633:	w2 = w1
     634:	w2 &= 0x3
     635:	r6 = *(u64 *)(r10 - 0x98)
; 		if (ct_entry_alive(entry))
     636:	if w2 == 0x3 goto +0x1e <LBB16_80>
     637:	w8 = 0x3c
; 	if (tcp) {
     638:	w2 = *(u32 *)(r10 - 0xf0)
     639:	if w2 != 0x6 goto +0x9 <LBB16_77>
; 		entry->seen_non_syn |= !syn;
     640:	w2 = *(u32 *)(r10 - 0xd8)
     641:	w2 ^= -0x1
     642:	w2 >>= 0x5
     643:	w2 &= 0x10
     644:	w1 |= w2
     645:	*(u16 *)(r7 + 0x24) = w1
; 		if (entry->seen_non_syn) {
     646:	w1 &= 0x10
     647:	if w1 == 0x0 goto +0x1 <LBB16_77>
     648:	w8 = 0x5460

0000000000001448 <LBB16_77>:
; 	__u32 now = (__u32)bpf_mono_now();
     649:	call 0x5
     650:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
     651:	w8 += w0
     652:	*(u32 *)(r7 + 0x20) = w8
; 	barrier();
     653:	w3 = *(u32 *)(r10 - 0xd8)
     654:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
     655:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     656:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
     657:	w1 = w2
     658:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
     659:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     660:	w3 += 0x5
     661:	if w3 < w0 goto +0x3 <LBB16_79>
     662:	w3 = w1
     663:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     664:	if w2 == w3 goto +0x2 <LBB16_80>

00000000000014c8 <LBB16_79>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
     665:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
     666:	*(u32 *)(r7 + 0x30) = w0

00000000000014d8 <LBB16_80>:
; 		if (dir == CT_SERVICE && entry->rev_nat_index == 0)
     667:	w1 = *(u16 *)(r7 + 0x26)
     668:	if w1 != 0x0 goto +0x2 <LBB16_82>
; 			entry->rev_nat_index = ct_state->rev_nat_index;
     669:	w1 = *(u32 *)(r10 - 0xc0)
     670:	*(u16 *)(r7 + 0x26) = w1

00000000000014f8 <LBB16_82>:
     671:	r1 = 0x1
; 		__sync_fetch_and_add(&entry->packets, 1);
     672:	lock *(u64 *)(r7 + 0x10) += r1
; 	return ctx->len;
     673:	w1 = *(u32 *)(r6 + 0x0)
; 		__sync_fetch_and_add(&entry->bytes, ctx_full_len(ctx));
     674:	lock *(u64 *)(r7 + 0x18) += r1
; 		switch (action) {
     675:	if w9 == 0x2 goto +0x16a <LBB16_91>
     676:	w8 = 0x0
; 		switch (action) {
     677:	if w9 != 0x1 goto +0x17f <LBB16_94>
; 	return entry->tx_closing || entry->rx_closing;
     678:	w1 = *(u16 *)(r7 + 0x24)
     679:	w2 = w1
     680:	w2 &= 0x3
; 			if (unlikely(ct_entry_closing(entry))) {
     681:	if w2 == 0x0 goto +0x17b <LBB16_94>
; 	entry->tx_flags_seen = 0;
     682:	*(u16 *)(r7 + 0x2a) = w8
; 				entry->seen_non_syn = false;
     683:	w1 &= 0xffec
     684:	*(u16 *)(r7 + 0x24) = w1
     685:	w9 = 0x3c
; 	if (tcp) {
     686:	w2 = *(u32 *)(r10 - 0xf0)
     687:	if w2 != 0x6 goto +0x8 <LBB16_88>
; 		entry->seen_non_syn |= !syn;
     688:	w2 = *(u32 *)(r10 - 0xd8)
     689:	w2 ^= -0x1
     690:	w2 >>= 0x5
     691:	w2 &= 0x10
     692:	w1 |= w2
     693:	*(u16 *)(r7 + 0x24) = w1
     694:	if w2 == 0x0 goto +0x1 <LBB16_88>
     695:	w9 = 0x5460

00000000000015c0 <LBB16_88>:
; 	__u32 now = (__u32)bpf_mono_now();
     696:	call 0x5
     697:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
     698:	w9 += w0
     699:	*(u32 *)(r7 + 0x20) = w9
; 	barrier();
     700:	w3 = *(u32 *)(r10 - 0xd8)
     701:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
     702:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     703:	w1 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
     704:	w2 = w1
     705:	w2 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
     706:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     707:	w3 += 0x5
     708:	if w3 < w0 goto +0x6 <LBB16_90>
     709:	w3 = w2
     710:	w3 &= 0xff
     711:	r4 = r1
     712:	w5 = 0x0
     713:	w1 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     714:	if w4 == w3 goto +0x163 <LBB16_95>

0000000000001658 <LBB16_90>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
     715:	*(u8 *)(r7 + 0x2a) = w2
; 			WRITE_ONCE(entry->last_tx_report, now);
     716:	*(u32 *)(r7 + 0x30) = w0
; 	barrier();
     717:	w5 = 0x0
     718:	w1 = 0x0
     719:	goto +0x15e <LBB16_95>

0000000000001680 <LBB16_56>:
     720:	r3 = r10
     721:	r3 += -0x10
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     722:	r1 = r6
     723:	w2 = 0x6
     724:	w4 = 0x6
     725:	w5 = 0x0
     726:	call 0x9
     727:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     728:	if w0 s< 0x0 goto +0x9 <LBB16_59>
     729:	r3 = r10
     730:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     731:	r1 = r6
     732:	w2 = 0x0
     733:	w4 = 0x6
     734:	w5 = 0x0
     735:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     736:	if w0 s< 0x0 goto +0x1 <LBB16_59>
     737:	w9 = 0x0

0000000000001710 <LBB16_59>:
; 	if (IS_ERR(ret))
     738:	if w9 s< 0x0 goto -0x193 <LBB16_245>
; 	return redirect(ifindex, flags);
     739:	w1 = 0x1
     740:	w2 = 0x0
     741:	call 0x17
     742:	w9 = w0
     743:	goto -0x198 <LBB16_245>

0000000000001740 <LBB16_261>:
; 		new_entry.bytes = bytes;
     744:	*(u64 *)(r10 - 0x40) = r7
     745:	r1 = 0x1
; 		new_entry.count = 1;
     746:	*(u64 *)(r10 - 0x48) = r1
     747:	r2 = r10
     748:	r2 += -0x70
     749:	r3 = r10
     750:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
     751:	r1 = 0x0 ll
     753:	w4 = 0x0
     754:	call 0x2
     755:	w9 = w8
     756:	goto +0xd <LBB16_269>

00000000000017a8 <LBB16_267>:
; 		new_entry.bytes = bytes;
     757:	*(u64 *)(r10 - 0x40) = r7
     758:	r1 = 0x1
; 		new_entry.count = 1;
     759:	*(u64 *)(r10 - 0x48) = r1
     760:	r2 = r10
     761:	r2 += -0x70
     762:	r3 = r10
     763:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
     764:	r1 = 0x0 ll
     766:	w4 = 0x0
     767:	call 0x2

0000000000001800 <LBB16_268>:
     768:	w9 = 0x0
     769:	r6 = *(u64 *)(r10 - 0x98)

0000000000001810 <LBB16_269>:
     770:	r8 = *(u64 *)(r10 - 0xa8)
     771:	w7 = *(u32 *)(r10 - 0xa0)
     772:	w1 = *(u32 *)(r10 - 0xb0)
     773:	if w1 == 0x32 goto +0xd0 <LBB16_296>

0000000000001830 <LBB16_271>:
     774:	w1 = 0x0
; 	struct endpoint_key key = {};
     775:	*(u32 *)(r10 - 0x38) = w1
; 	key.ip6 = *ip6;
     776:	w1 = *(u8 *)(r8 + 0x18)
     777:	w3 = *(u8 *)(r8 + 0x19)
     778:	r3 <<= 0x8
     779:	r3 |= r1
     780:	w1 = *(u8 *)(r8 + 0x1a)
     781:	r1 <<= 0x10
     782:	w2 = *(u8 *)(r8 + 0x1b)
     783:	r2 <<= 0x18
     784:	r2 |= r1
     785:	r2 |= r3
     786:	w3 = *(u8 *)(r8 + 0x1d)
     787:	w3 <<= 0x8
     788:	w1 = *(u8 *)(r8 + 0x1c)
     789:	w3 |= w1
     790:	w4 = *(u8 *)(r8 + 0x1e)
     791:	w4 <<= 0x10
     792:	w1 = *(u8 *)(r8 + 0x1f)
     793:	w1 <<= 0x18
     794:	w1 |= w4
     795:	w1 |= w3
     796:	r1 <<= 0x20
     797:	r1 |= r2
     798:	w2 = *(u8 *)(r8 + 0x20)
     799:	w4 = *(u8 *)(r8 + 0x21)
     800:	r4 <<= 0x8
     801:	r4 |= r2
     802:	w3 = *(u8 *)(r8 + 0x22)
     803:	r3 <<= 0x10
     804:	w2 = *(u8 *)(r8 + 0x23)
     805:	r2 <<= 0x18
     806:	r2 |= r3
     807:	w3 = *(u8 *)(r8 + 0x27)
     808:	w5 = *(u8 *)(r8 + 0x26)
     809:	w0 = *(u8 *)(r8 + 0x24)
     810:	w6 = *(u8 *)(r8 + 0x25)
     811:	w7 = 0x2
; 	key.family = ENDPOINT_KEY_IPV6;
     812:	*(u8 *)(r10 - 0x38) = w7
; 	key.ip6 = *ip6;
     813:	*(u64 *)(r10 - 0x48) = r1
     814:	r2 |= r4
     815:	w6 <<= 0x8
     816:	w6 |= w0
     817:	w5 <<= 0x10
     818:	w3 <<= 0x18
     819:	w3 |= w5
     820:	w3 |= w6
     821:	r3 <<= 0x20
     822:	r3 |= r2
     823:	*(u64 *)(r10 - 0x40) = r3
     824:	r2 = r10
     825:	r2 += -0x48
; 	return map_lookup_elem(&ENDPOINTS_MAP, &key);
     826:	r1 = 0x0 ll
     828:	call 0x1
     829:	r7 = r0
; 	if (ep && !(ep->flags & ENDPOINT_MASK_HOST_DELIVERY))
     830:	if r7 == 0x0 goto +0x2c <LBB16_285>
     831:	w1 = *(u32 *)(r7 + 0x8)
     832:	w1 &= 0x3
     833:	if w1 != 0x0 goto +0x29 <LBB16_285>
; 	mac_t router_mac = ep->node_mac;
     834:	r1 = *(u64 *)(r7 + 0x18)
     835:	*(u64 *)(r10 - 0x48) = r1
; 	mac_t lxc_mac = ep->mac;
     836:	r1 = *(u64 *)(r7 + 0x10)
     837:	*(u64 *)(r10 - 0x70) = r1
     838:	r3 = r10
     839:	r3 += -0x88
     840:	r6 = *(u64 *)(r10 - 0x98)
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     841:	r1 = r6
     842:	w2 = 0x7
     843:	w4 = 0x1
     844:	call 0x1a
     845:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     846:	if w0 s< 0x0 goto +0xf <LBB16_276>
     847:	w9 = -0xc4
; 	if (hl <= 1)
     848:	w1 = *(u8 *)(r10 - 0x88)
     849:	if w1 < 0x2 goto +0xc <LBB16_276>
; 	hl--;
     850:	w1 += -0x1
     851:	*(u8 *)(r10 - 0x88) = w1
     852:	r3 = r10
     853:	r3 += -0x88
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     854:	r1 = r6
     855:	w2 = 0x7
     856:	w4 = 0x1
     857:	w5 = 0x1
     858:	call 0x9
     859:	w9 = w0
     860:	w9 s>>= 0x1f
     861:	w9 &= -0x8d

0000000000001af0 <LBB16_276>:
; 	if (IS_ERR(ret)) {
     862:	if w9 s> -0x1 goto +0x55 <LBB16_279>
; 		if (ret == DROP_TTL_EXCEEDED)
     863:	if w9 != -0xc4 goto +0x66 <LBB16_282>
     864:	w1 = 0x1
; 	ctx->cb[off] = data;
     865:	*(u32 *)(r6 + 0x34) = w1
     866:	w1 = 0x0
     867:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     868:	r1 = r6
     869:	r2 = 0x0 ll
     871:	r3 = 0x5
     872:	call 0xc
     873:	w9 = -0x8c
     874:	goto +0x5b <LBB16_282>

0000000000001b58 <LBB16_285>:
     875:	r1 = 0x568803a772ce ll
; 		union macaddr host_mac = HOST_IFINDEX_MAC;
     877:	*(u64 *)(r10 - 0x48) = r1
; 		union macaddr router_mac = THIS_INTERFACE_MAC;
     878:	r1 = 0x0 ll
     880:	w1 = *(u32 *)(r1 + 0x0)
     881:	*(u32 *)(r10 - 0x70) = w1
     882:	r1 = 0x0 ll
     884:	w1 = *(u32 *)(r1 + 0x0)
     885:	*(u16 *)(r10 - 0x6c) = w1
     886:	r3 = r10
; 		union macaddr host_mac = HOST_IFINDEX_MAC;
     887:	r3 += -0x88
     888:	r6 = *(u64 *)(r10 - 0x98)
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     889:	r1 = r6
     890:	w2 = 0x7
     891:	w4 = 0x1
     892:	call 0x1a
     893:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     894:	if w0 s< 0x0 goto +0xf <LBB16_288>
     895:	w9 = -0xc4
; 	if (hl <= 1)
     896:	w1 = *(u8 *)(r10 - 0x88)
     897:	if w1 < 0x2 goto +0xc <LBB16_288>
; 	hl--;
     898:	w1 += -0x1
     899:	*(u8 *)(r10 - 0x88) = w1
     900:	r3 = r10
     901:	r3 += -0x88
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     902:	r1 = r6
     903:	w2 = 0x7
     904:	w4 = 0x1
     905:	w5 = 0x1
     906:	call 0x9
     907:	w9 = w0
     908:	w9 s>>= 0x1f
     909:	w9 &= -0x8d

0000000000001c70 <LBB16_288>:
     910:	w7 = *(u32 *)(r10 - 0xa0)
; 	if (IS_ERR(ret)) {
     911:	if w9 s> -0x1 goto +0xc <LBB16_291>
; 		if (ret == DROP_TTL_EXCEEDED)
     912:	if w9 != -0xc4 goto +0x1d <LBB16_294>
     913:	w1 = 0x1
; 	ctx->cb[off] = data;
     914:	*(u32 *)(r6 + 0x34) = w1
     915:	w1 = 0x0
     916:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     917:	r1 = r6
     918:	r2 = 0x0 ll
     920:	r3 = 0x5
     921:	call 0xc
     922:	w9 = -0x8c
     923:	goto +0x12 <LBB16_294>

0000000000001ce0 <LBB16_291>:
     924:	r3 = r10
     925:	r3 += -0x70
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     926:	r1 = r6
     927:	w2 = 0x6
     928:	w4 = 0x6
     929:	w5 = 0x0
     930:	call 0x9
     931:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     932:	if w0 s< 0x0 goto +0x9 <LBB16_294>
     933:	r3 = r10
     934:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     935:	r1 = r6
     936:	w2 = 0x0
     937:	w4 = 0x6
     938:	w5 = 0x0
     939:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     940:	if w0 s< 0x0 goto +0x1 <LBB16_294>
     941:	w9 = 0x0

0000000000001d70 <LBB16_294>:
; 		if (ret != CTX_ACT_OK)
     942:	if w9 != 0x0 goto +0x27 <LBB16_296>
; 	return redirect(ifindex, flags);
     943:	w1 = 0x1
     944:	w2 = 0x0
     945:	call 0x17
     946:	w9 = w0
     947:	goto +0x22 <LBB16_296>

0000000000001da0 <LBB16_279>:
     948:	r3 = r10
     949:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     950:	r1 = r6
     951:	w2 = 0x6
     952:	w4 = 0x6
     953:	w5 = 0x0
     954:	call 0x9
     955:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     956:	if w0 s< 0x0 goto +0x9 <LBB16_282>
     957:	r3 = r10
     958:	r3 += -0x70
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     959:	r1 = r6
     960:	w2 = 0x0
     961:	w4 = 0x6
     962:	w5 = 0x0
     963:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     964:	if w0 s< 0x0 goto +0x1 <LBB16_282>
     965:	w9 = 0x0

0000000000001e30 <LBB16_282>:
; 	if (ret != CTX_ACT_OK)
     966:	if w9 != 0x0 goto +0xe <LBB16_284>
     967:	w1 = 0x1
; 	ctx->cb[off] = data;
     968:	*(u32 *)(r6 + 0x40) = w1
     969:	*(u32 *)(r6 + 0x34) = w1
     970:	w1 = *(u32 *)(r10 - 0x90)
     971:	*(u32 *)(r6 + 0x30) = w1
     972:	w1 = 0x0
; 	ctx->cb[off] = data;
     973:	*(u32 *)(r6 + 0x3c) = w1
     974:	*(u32 *)(r6 + 0x38) = w1
; 	return tail_call_policy(ctx, ep->lxc_id);
     975:	w3 = *(u16 *)(r7 + 0x6)
; 	tail_call(ctx, map, slot);
     976:	r1 = r6
     977:	r2 = 0x0 ll
     979:	call 0xc
     980:	w9 = -0xcb

0000000000001ea8 <LBB16_284>:
     981:	w7 = *(u32 *)(r10 - 0xa0)

0000000000001eb0 <LBB16_296>:
; 	if (IS_ERR(ret))
     982:	if w9 s< 0x0 goto +0x1 <LBB16_298>
     983:	if w9 != 0x2 goto +0x375 <LBB16_302>

0000000000001ec0 <LBB16_298>:
     984:	w1 = 0xb80302
; 	ctx->cb[off] = data;
     985:	*(u32 *)(r6 + 0x40) = w1
     986:	w1 = 0x0
     987:	*(u32 *)(r6 + 0x3c) = w1
     988:	*(u32 *)(r6 + 0x34) = w1
     989:	w1 = *(u32 *)(r10 - 0x90)
     990:	*(u32 *)(r6 + 0x30) = w1
; 		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
     991:	w1 = w9
     992:	w1 s>>= 0x1f
     993:	w9 ^= w1
     994:	w9 -= w1
     995:	w7 &= 0xff
     996:	w7 <<= 0x8
     997:	w1 = w9
     998:	w1 &= 0xff
     999:	w1 |= w7
; 	ctx->cb[off] = data;
    1000:	*(u32 *)(r6 + 0x38) = w1
    1001:	r7 = r6
; 	return ctx->len;
    1002:	w6 = *(u32 *)(r6 + 0x0)
    1003:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
    1004:	*(u64 *)(r10 - 0x40) = r1
    1005:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
    1006:	*(u64 *)(r10 - 0x70) = r1
; 	key.reason = reason;
    1007:	*(u8 *)(r10 - 0x70) = w9
    1008:	w1 = 0x3
; 	key.file   = file;
    1009:	*(u8 *)(r10 - 0x6c) = w1
    1010:	w1 = 0xb8
; 	key.line   = line;
    1011:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
    1012:	w1 = *(u8 *)(r10 - 0x6f)
    1013:	w1 &= 0xfc
    1014:	w1 |= 0x1
    1015:	*(u8 *)(r10 - 0x6f) = w1
    1016:	r2 = r10
    1017:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
    1018:	r1 = 0x0 ll
    1020:	call 0x1
; 	if (entry) {
    1021:	if r0 == 0x0 goto +0x33e <LBB16_300>
; 		entry->count += 1;
    1022:	r1 = *(u64 *)(r0 + 0x0)
    1023:	r1 += 0x1
    1024:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
    1025:	r1 = *(u64 *)(r0 + 0x8)
    1026:	r1 += r6
    1027:	*(u64 *)(r0 + 0x8) = r1
    1028:	goto +0x342 <LBB16_301>

0000000000002028 <LBB16_27>:
    1029:	r3 = r10
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
    1030:	r3 += -0x48
    1031:	r1 = *(u64 *)(r10 - 0x98)
    1032:	w2 = w8
    1033:	w4 = 0x2
    1034:	call 0x1a
    1035:	if w0 s< 0x0 goto -0x380 <LBB16_31>
    1036:	w7 = -0x9c
    1037:	goto -0x382 <LBB16_31>

0000000000002070 <LBB16_91>:
; 				entry->rx_closing = 1;
    1038:	w1 = *(u16 *)(r7 + 0x24)
; 				entry->tx_closing = 1;
    1039:	w1 |= 0x3
    1040:	*(u16 *)(r7 + 0x24) = w1
; 	__u32 now = (__u32)bpf_mono_now();
    1041:	call 0x5
    1042:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    1043:	w1 = w0
    1044:	w1 += 0xa
    1045:	*(u32 *)(r7 + 0x20) = w1
    1046:	w8 = 0x100
    1047:	w3 = *(u32 *)(r10 - 0xd8)
    1048:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    1049:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1050:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    1051:	w1 = w2
    1052:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    1053:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1054:	w3 += 0x5
    1055:	if w3 < w0 goto +0x3 <LBB16_93>
    1056:	w3 = w1
    1057:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1058:	if w2 == w3 goto +0x2 <LBB16_94>

0000000000002118 <LBB16_93>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    1059:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    1060:	*(u32 *)(r7 + 0x30) = w0

0000000000002128 <LBB16_94>:
    1061:	w1 = *(u32 *)(r10 - 0xf8)
; 		state->syn = syn;
    1062:	w1 >>= 0x6
    1063:	w8 |= w1
    1064:	w1 = 0x1
    1065:	w2 = 0x0
; 	state->rev_nat_index = entry->rev_nat_index;
    1066:	*(u32 *)(r10 - 0xa0) = w2
    1067:	w2 = *(u16 *)(r7 + 0x26)
; 		state->backend_id = (__u32)entry->backend_id;
    1068:	*(u32 *)(r10 - 0xc0) = w2
    1069:	r5 = *(u64 *)(r7 + 0x8)

0000000000002170 <LBB16_95>:
    1070:	r6 = *(u64 *)(r10 - 0x98)
; 		if (ret != CT_NEW) {
    1071:	w2 = *(u32 *)(r10 - 0xa0)
    1072:	if w2 != 0x0 goto +0x5 <LBB16_98>
; 			if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1073:	w2 = *(u8 *)(r10 - 0x4b)
    1074:	w2 &= 0x2
    1075:	w1 = 0x2
    1076:	if w2 == 0x0 goto +0x1 <LBB16_98>
    1077:	w1 = 0x3

00000000000021b0 <LBB16_98>:
; 	cilium_dbg(ctx, DBG_CT_VERDICT, ret,
    1078:	w1 &= 0xff
    1079:	w7 = w8

00000000000021c0 <LBB16_99>:
    1080:	w2 = 0x0
    1081:	*(u32 *)(r10 - 0xa0) = w2
    1082:	w9 = w1
; 	if (ret < 0)
    1083:	if w1 s< 0x0 goto +0x33d <LBB16_169>
; 	switch (ret) {
    1084:	if w1 == 0x2 goto +0x56 <LBB16_135>
    1085:	w9 = -0xa3
; 	switch (ret) {
    1086:	*(u32 *)(r10 - 0xa0) = w2
    1087:	if w1 != 0x0 goto +0x339 <LBB16_169>
    1088:	w9 = -0x9e
; 		if (unlikely(svc->count == 0))
    1089:	r1 = *(u64 *)(r10 - 0xb8)
    1090:	w1 = *(u16 *)(r1 + 0x4)
    1091:	*(u32 *)(r10 - 0xa0) = w2
    1092:	if w1 == 0x0 goto +0x334 <LBB16_169>
    1093:	w3 = 0x0
; 	return svc->flags & SVC_FLAG_AFFINITY;
    1094:	r1 = *(u64 *)(r10 - 0xb8)
    1095:	w1 = *(u8 *)(r1 + 0x8)
    1096:	w1 &= 0x10
; 		if (lb6_svc_is_affinity(svc)) {
    1097:	if w1 == 0x0 goto +0x14e <LBB16_113>
    1098:	r1 = 0x0
; 	struct lb6_affinity_key key = {
    1099:	*(u64 *)(r10 - 0x38) = r1
    1100:	*(u64 *)(r10 - 0x40) = r1
    1101:	*(u64 *)(r10 - 0x48) = r1
; 		.rev_nat_id	= svc->rev_nat_index,
    1102:	r1 = *(u64 *)(r10 - 0xb8)
    1103:	w1 = *(u16 *)(r1 + 0x6)
; 	struct lb6_affinity_key key = {
    1104:	*(u16 *)(r10 - 0x38) = w1
; 	dst->d2 = src->d2;
    1105:	r1 = *(u64 *)(r10 - 0xe8)
    1106:	*(u64 *)(r10 - 0x40) = r1
; 	dst->d1 = src->d1;
    1107:	r1 = *(u64 *)(r10 - 0xe0)
    1108:	*(u64 *)(r10 - 0x48) = r1
; 	struct lb6_affinity_key key = {
    1109:	w1 = *(u8 *)(r10 - 0x36)
    1110:	w1 &= 0xfe
    1111:	*(u8 *)(r10 - 0x36) = w1
    1112:	r2 = r10
    1113:	r2 += -0x48
; 	val = map_lookup_elem(&LB6_AFFINITY_MAP, &key);
    1114:	r1 = 0x0 ll
    1116:	call 0x1
    1117:	r7 = r0
    1118:	w8 = 0x0
; 	if (val != NULL) {
    1119:	if r7 == 0x0 goto +0x12c <LBB16_110>
; 		__u32 now = (__u32)bpf_mono_now();
    1120:	call 0x5
; 			.backend_id	= val->backend_id,
    1121:	w1 = *(u8 *)(r7 + 0x9)
    1122:	w1 <<= 0x8
    1123:	w2 = *(u8 *)(r7 + 0x8)
    1124:	w1 |= w2
    1125:	w2 = *(u8 *)(r7 + 0xa)
    1126:	w2 <<= 0x10
    1127:	w3 = *(u8 *)(r7 + 0xb)
    1128:	w3 <<= 0x18
    1129:	w3 |= w2
    1130:	w3 |= w1
; 		struct lb_affinity_match match = {
    1131:	*(u32 *)(r10 - 0x10) = w3
    1132:	r5 = *(u64 *)(r10 - 0xb8)
; 			.rev_nat_id	= svc->rev_nat_index,
    1133:	w1 = *(u16 *)(r5 + 0x6)
; 		struct lb_affinity_match match = {
    1134:	*(u16 *)(r10 - 0xa) = w8
    1135:	*(u16 *)(r10 - 0xc) = w1
; 		if (READ_ONCE(val->last_used) +
    1136:	w1 = *(u8 *)(r7 + 0x0)
    1137:	w2 = *(u8 *)(r7 + 0x1)
    1138:	r2 <<= 0x8
    1139:	r2 |= r1
    1140:	w3 = *(u8 *)(r7 + 0x2)
    1141:	r3 <<= 0x10
    1142:	w1 = *(u8 *)(r7 + 0x3)
    1143:	r1 <<= 0x18
    1144:	r1 |= r3
    1145:	r1 |= r2
    1146:	w2 = *(u8 *)(r7 + 0x4)
    1147:	w3 = *(u8 *)(r7 + 0x5)
    1148:	w3 <<= 0x8
    1149:	w3 |= w2
    1150:	w4 = *(u8 *)(r7 + 0x6)
    1151:	w4 <<= 0x10
    1152:	w2 = *(u8 *)(r7 + 0x7)
    1153:	w2 <<= 0x18
    1154:	w2 |= w4
    1155:	w2 |= w3
    1156:	r2 <<= 0x20
    1157:	r2 |= r1
; 	return svc->affinity_timeout & AFFINITY_TIMEOUT_MASK;
    1158:	w1 = *(u32 *)(r5 + 0x0)
; 		    bpf_sec_to_mono(lb6_affinity_timeout(svc)) <= now) {
    1159:	r1 &= 0xffffff
; 		if (READ_ONCE(val->last_used) +
    1160:	r2 += r1
; 		__u32 now = (__u32)bpf_mono_now();
    1161:	r0 /= 0x3b9aca00
; 		    bpf_sec_to_mono(lb6_affinity_timeout(svc)) <= now) {
    1162:	r0 <<= 0x20
    1163:	r0 >>= 0x20
; 		if (READ_ONCE(val->last_used) +
    1164:	if r2 > r0 goto +0xde <LBB16_107>

0000000000002468 <LBB16_106>:
    1165:	r2 = r10
    1166:	r2 += -0x48
    1167:	r1 = 0x0 ll
    1169:	call 0x3
    1170:	goto +0xf9 <LBB16_110>

0000000000002498 <LBB16_135>:
    1171:	*(u32 *)(r10 - 0x48) = w5
    1172:	r2 = r10
    1173:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1174:	r1 = 0x0 ll
    1176:	r8 = r5
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1177:	call 0x1
    1178:	r2 = r8
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1179:	r3 = r0
; 		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
    1180:	if r3 == 0x0 goto +0x6 <LBB16_138>
    1181:	w1 = 0x0
; 		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
    1182:	*(u32 *)(r10 - 0xa0) = w1
    1183:	w1 = *(u8 *)(r3 + 0x13)
    1184:	if w1 == 0x0 goto +0x223 <LBB16_149>
; 			if (backend && !state->syn)
    1185:	w7 &= 0x8
    1186:	if w7 == 0x0 goto +0x221 <LBB16_149>

0000000000002518 <LBB16_138>:
    1187:	w9 = -0x9e
; 			if (unlikely(svc->count == 0))
    1188:	r1 = *(u64 *)(r10 - 0xb8)
    1189:	w1 = *(u16 *)(r1 + 0x4)
    1190:	w2 = 0x0
    1191:	*(u32 *)(r10 - 0xa0) = w2
    1192:	if w1 == 0x0 goto +0x2d0 <LBB16_169>
    1193:	w7 = 0x0
; 	return svc->affinity_timeout >> LB_ALGORITHM_SHIFT;
    1194:	r1 = *(u64 *)(r10 - 0xb8)
    1195:	w1 = *(u32 *)(r1 + 0x0)
    1196:	w1 >>= 0x18
; 	switch (lb6_algorithm(svc)) {
    1197:	if w1 == 0x1 goto +0x2a1 <LBB16_144>
    1198:	if w1 != 0x2 goto +0x2ad <LBB16_146>
    1199:	w1 = 0x0
    1200:	w7 = 0x0
; 	__u32 zero = 0, index = svc->rev_nat_index;
    1201:	*(u32 *)(r10 - 0x48) = w1
    1202:	r1 = *(u64 *)(r10 - 0xb8)
    1203:	w1 = *(u16 *)(r1 + 0x6)
    1204:	*(u32 *)(r10 - 0x10) = w1
    1205:	r2 = r10
    1206:	r2 += -0x10
; 	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
    1207:	r1 = 0x0 ll
    1209:	call 0x1
; 	if (unlikely(!maglev_lut))
    1210:	if r0 == 0x0 goto +0x2a1 <LBB16_146>
    1211:	r2 = r10
; 	backend_ids = map_lookup_elem(maglev_lut, &zero);
    1212:	r2 += -0x48
    1213:	r1 = r0
    1214:	call 0x1
; 	if (unlikely(!backend_ids))
    1215:	if r0 == 0x0 goto +0x29c <LBB16_146>
; 	c = tuple->saddr.p3;
    1216:	w1 = *(u32 *)(r10 - 0x58)
; 	return (word << shift) | (word >> ((-shift) & 31));
    1217:	w2 = w1
    1218:	w2 >>= 0x1c
    1219:	w3 = w1
    1220:	w3 <<= 0x4
    1221:	w3 |= w2
; 	a = tuple->saddr.p1;
    1222:	w2 = *(u32 *)(r10 - 0x60)
; 	__jhash_mix(a, b, c);
    1223:	w2 -= w1
    1224:	w2 ^= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1225:	w3 = w2
    1226:	w3 >>= 0x1a
    1227:	w5 = w2
    1228:	w5 <<= 0x6
    1229:	w5 |= w3
; 	b = tuple->saddr.p2;
    1230:	w3 = *(u32 *)(r10 - 0x5c)
; 	__jhash_mix(a, b, c);
    1231:	w4 = w3
    1232:	w4 -= w2
    1233:	w4 ^= w5
    1234:	w1 += w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1235:	w3 = w4
    1236:	w3 >>= 0x18
    1237:	w6 = w4
    1238:	w6 <<= 0x8
    1239:	w6 |= w3
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1240:	w5 = *(u16 *)(r10 - 0x50)
    1241:	w5 <<= 0x10
    1242:	w3 = *(u16 *)(r10 - 0x4e)
    1243:	w5 |= w3
; 	__jhash_mix(a, b, c);
    1244:	w2 += w1
    1245:	w1 -= w4
    1246:	w1 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1247:	w3 = w1
    1248:	w3 >>= 0x10
    1249:	w6 = w1
    1250:	w6 <<= 0x10
    1251:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1252:	w4 += w2
    1253:	w2 -= w1
    1254:	w2 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1255:	w3 = w2
    1256:	w3 >>= 0xd
    1257:	w6 = w2
    1258:	w6 <<= 0x13
    1259:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1260:	w1 += w4
    1261:	w4 -= w2
    1262:	w4 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1263:	w3 = w4
    1264:	w3 >>= 0x1c
    1265:	w6 = w4
    1266:	w6 <<= 0x4
    1267:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1268:	w2 += w1
    1269:	w1 -= w4
    1270:	w1 ^= w6
; 	c += tuple->nexthdr;
    1271:	w3 = *(u8 *)(r10 - 0x4c)
    1272:	w1 += w3
; 	__jhash_mix(a, b, c);
    1273:	w3 = w2
    1274:	w3 += w5
; 	a += tuple->saddr.p4;
    1275:	w5 = *(u32 *)(r10 - 0x54)
    1276:	w2 += w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1277:	w5 = w1
    1278:	w5 >>= 0x1c
    1279:	w6 = w1
    1280:	w6 <<= 0x4
    1281:	w6 |= w5
; 	__jhash_mix(a, b, c);
    1282:	w2 -= w1
    1283:	w2 ^= w6
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1284:	w3 += w4
; 	return (word << shift) | (word >> ((-shift) & 31));
    1285:	w4 = w2
    1286:	w4 >>= 0x1a
    1287:	w5 = w2
    1288:	w5 <<= 0x6
    1289:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1290:	w1 += w3
    1291:	w3 -= w2
    1292:	w3 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1293:	w4 = w3
    1294:	w4 >>= 0x18
    1295:	w5 = w3
    1296:	w5 <<= 0x8
    1297:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1298:	w2 += w1
    1299:	w1 -= w3
    1300:	w1 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1301:	w4 = w1
    1302:	w4 >>= 0x10
    1303:	w5 = w1
    1304:	w5 <<= 0x10
    1305:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1306:	w3 += w2
    1307:	w2 -= w1
    1308:	w2 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1309:	w4 = w2
    1310:	w4 >>= 0xd
    1311:	w5 = w2
    1312:	w5 <<= 0x13
    1313:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1314:	w1 += w3
    1315:	w3 -= w2
    1316:	w3 ^= w5
    1317:	w2 += w1
    1318:	w4 = w3
    1319:	w4 += w2
; 	return (word << shift) | (word >> ((-shift) & 31));
    1320:	w5 = w4
    1321:	w5 >>= 0x12
    1322:	w6 = w4
    1323:	w6 <<= 0xe
    1324:	w6 |= w5
    1325:	w5 = w3
    1326:	w5 >>= 0x1c
; 	__jhash_mix(a, b, c);
    1327:	w1 -= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1328:	w3 <<= 0x4
    1329:	w3 |= w5
; 	__jhash_mix(a, b, c);
    1330:	w1 ^= w3
; 	__jhash_final(a, b, c);
    1331:	w1 ^= w4
    1332:	w1 -= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1333:	w3 = w1
    1334:	w3 >>= 0x15
    1335:	w5 = w1
    1336:	w5 <<= 0xb
    1337:	w5 |= w3
; 	a += HASH_INIT6_SEED;
    1338:	w2 += 0xeb9f
; 	__jhash_final(a, b, c);
    1339:	w3 = w1
    1340:	w3 ^= w2
    1341:	w3 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1342:	w2 = w3
    1343:	w2 >>= 0x7
    1344:	w5 = w3
    1345:	w5 <<= 0x19
    1346:	w5 |= w2
; 	__jhash_final(a, b, c);
    1347:	w2 = w3
    1348:	w2 ^= w4
    1349:	w2 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1350:	w4 = w2
    1351:	w4 >>= 0x10
    1352:	w5 = w2
    1353:	w5 <<= 0x10
    1354:	w5 |= w4
; 	__jhash_final(a, b, c);
    1355:	w4 = w2
    1356:	w4 ^= w1
    1357:	w4 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1358:	w1 = w4
    1359:	w1 >>= 0x1c
    1360:	w5 = w4
    1361:	w5 <<= 0x4
    1362:	w5 |= w1
; 	__jhash_final(a, b, c);
    1363:	w1 = w4
    1364:	w1 ^= w3
    1365:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1366:	w3 = w1
    1367:	w3 >>= 0x12
    1368:	w5 = w1
    1369:	w5 <<= 0xe
    1370:	w5 |= w3
; 	__jhash_final(a, b, c);
    1371:	w1 ^= w2
    1372:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1373:	w2 = w1
    1374:	w2 >>= 0x8
    1375:	w3 = w1
    1376:	w3 <<= 0x18
    1377:	w3 |= w2
; 	__jhash_final(a, b, c);
    1378:	w1 ^= w4
    1379:	w1 -= w3
; 	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
    1380:	w1 %= 0x7fed
    1381:	*(u32 *)(r10 - 0x10) = w1
; 	asm volatile("%[index] <<= 2\n\t"
    1382:	r1 <<= 0x2
    1383:	if r1 > 0x1ffb0 goto +0x1 <LBB16_138+0x630>
    1384:	r0 += r1
    1385:	w7 = *(u32 *)(r0 + 0x0)
    1386:	goto +0x1f1 <LBB16_146>

0000000000002b58 <LBB16_107>:
    1387:	*(u64 *)(r10 - 0xa0) = r0
    1388:	r2 = r10
; 		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
    1389:	r2 += -0x10
    1390:	r1 = 0x0 ll
    1392:	call 0x1
    1393:	if r0 != 0x0 goto +0x1 <LBB16_109>
    1394:	goto -0xe6 <LBB16_106>

0000000000002b98 <LBB16_109>:
    1395:	r1 = 0x0
; 		WRITE_ONCE(val->last_used, now);
    1396:	*(u8 *)(r7 + 0x7) = w1
    1397:	*(u8 *)(r7 + 0x6) = w1
    1398:	*(u8 *)(r7 + 0x5) = w1
    1399:	*(u8 *)(r7 + 0x4) = w1
    1400:	r2 = *(u64 *)(r10 - 0xa0)
    1401:	*(u8 *)(r7 + 0x0) = w2
    1402:	r1 = r2
    1403:	r1 >>= 0x18
    1404:	*(u8 *)(r7 + 0x3) = w1
    1405:	r1 = r2
    1406:	r1 >>= 0x10
    1407:	*(u8 *)(r7 + 0x2) = w1
    1408:	r2 >>= 0x8
    1409:	*(u8 *)(r7 + 0x1) = w2
; 		return val->backend_id;
    1410:	w1 = *(u8 *)(r7 + 0x9)
    1411:	w1 <<= 0x8
    1412:	w2 = *(u8 *)(r7 + 0x8)
    1413:	w1 |= w2
    1414:	w2 = *(u8 *)(r7 + 0xa)
    1415:	w2 <<= 0x10
    1416:	w8 = *(u8 *)(r7 + 0xb)
    1417:	w8 <<= 0x18
    1418:	w8 |= w2
    1419:	w8 |= w1

0000000000002c60 <LBB16_110>:
    1420:	w3 = 0x0
; 			if (backend_id != 0) {
    1421:	if w8 == 0x0 goto +0xa <LBB16_113>
    1422:	*(u32 *)(r10 - 0x48) = w8
    1423:	r2 = r10
    1424:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1425:	r1 = 0x0 ll
    1427:	call 0x1
    1428:	w3 = w8
; 				if (backend == NULL)
    1429:	if r0 != 0x0 goto +0x2 <LBB16_113>
    1430:	r0 = 0x0
    1431:	w3 = 0x0

0000000000002cc0 <LBB16_113>:
; 		if (backend_id == 0) {
    1432:	if w3 != 0x0 goto +0xd9 <LBB16_123>
    1433:	w8 = 0x0
    1434:	r7 = *(u64 *)(r10 - 0xb8)
; 	return svc->affinity_timeout >> LB_ALGORITHM_SHIFT;
    1435:	w1 = *(u32 *)(r7 + 0x0)
    1436:	w1 >>= 0x18
; 	switch (lb6_algorithm(svc)) {
    1437:	if w1 == 0x1 goto +0xbd <LBB16_120>
    1438:	if w1 != 0x2 goto +0xc9 <LBB16_122>
    1439:	w1 = 0x0
    1440:	w8 = 0x0
; 	__u32 zero = 0, index = svc->rev_nat_index;
    1441:	*(u32 *)(r10 - 0x48) = w1
    1442:	w1 = *(u16 *)(r7 + 0x6)
    1443:	*(u32 *)(r10 - 0x10) = w1
    1444:	r2 = r10
    1445:	r2 += -0x10
; 	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
    1446:	r1 = 0x0 ll
    1448:	call 0x1
; 	if (unlikely(!maglev_lut))
    1449:	if r0 == 0x0 goto +0xaf <LBB16_119>
    1450:	r2 = r10
; 	backend_ids = map_lookup_elem(maglev_lut, &zero);
    1451:	r2 += -0x48
    1452:	r1 = r0
    1453:	call 0x1
; 	if (unlikely(!backend_ids))
    1454:	if r0 == 0x0 goto +0xaa <LBB16_119>
; 	c = tuple->saddr.p3;
    1455:	w1 = *(u32 *)(r10 - 0x58)
; 	return (word << shift) | (word >> ((-shift) & 31));
    1456:	w2 = w1
    1457:	w2 >>= 0x1c
    1458:	w3 = w1
    1459:	w3 <<= 0x4
    1460:	w3 |= w2
; 	a = tuple->saddr.p1;
    1461:	w2 = *(u32 *)(r10 - 0x60)
; 	__jhash_mix(a, b, c);
    1462:	w2 -= w1
    1463:	w2 ^= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1464:	w3 = w2
    1465:	w3 >>= 0x1a
    1466:	w5 = w2
    1467:	w5 <<= 0x6
    1468:	w5 |= w3
; 	b = tuple->saddr.p2;
    1469:	w3 = *(u32 *)(r10 - 0x5c)
; 	__jhash_mix(a, b, c);
    1470:	w4 = w3
    1471:	w4 -= w2
    1472:	w4 ^= w5
    1473:	w1 += w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1474:	w3 = w4
    1475:	w3 >>= 0x18
    1476:	w6 = w4
    1477:	w6 <<= 0x8
    1478:	w6 |= w3
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1479:	w5 = *(u16 *)(r10 - 0x50)
    1480:	w5 <<= 0x10
    1481:	w3 = *(u16 *)(r10 - 0x4e)
    1482:	w5 |= w3
; 	__jhash_mix(a, b, c);
    1483:	w2 += w1
    1484:	w1 -= w4
    1485:	w1 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1486:	w3 = w1
    1487:	w3 >>= 0x10
    1488:	w6 = w1
    1489:	w6 <<= 0x10
    1490:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1491:	w4 += w2
    1492:	w2 -= w1
    1493:	w2 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1494:	w3 = w2
    1495:	w3 >>= 0xd
    1496:	w6 = w2
    1497:	w6 <<= 0x13
    1498:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1499:	w1 += w4
    1500:	w4 -= w2
    1501:	w4 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1502:	w3 = w4
    1503:	w3 >>= 0x1c
    1504:	w6 = w4
    1505:	w6 <<= 0x4
    1506:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1507:	w2 += w1
    1508:	w1 -= w4
    1509:	w1 ^= w6
; 	c += tuple->nexthdr;
    1510:	w3 = *(u8 *)(r10 - 0x4c)
    1511:	w1 += w3
; 	__jhash_mix(a, b, c);
    1512:	w3 = w2
    1513:	w3 += w5
; 	a += tuple->saddr.p4;
    1514:	w5 = *(u32 *)(r10 - 0x54)
    1515:	w2 += w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1516:	w5 = w1
    1517:	w5 >>= 0x1c
    1518:	w6 = w1
    1519:	w6 <<= 0x4
    1520:	w6 |= w5
; 	__jhash_mix(a, b, c);
    1521:	w2 -= w1
    1522:	w2 ^= w6
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1523:	w3 += w4
; 	return (word << shift) | (word >> ((-shift) & 31));
    1524:	w4 = w2
    1525:	w4 >>= 0x1a
    1526:	w5 = w2
    1527:	w5 <<= 0x6
    1528:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1529:	w1 += w3
    1530:	w3 -= w2
    1531:	w3 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1532:	w4 = w3
    1533:	w4 >>= 0x18
    1534:	w5 = w3
    1535:	w5 <<= 0x8
    1536:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1537:	w2 += w1
    1538:	w1 -= w3
    1539:	w1 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1540:	w4 = w1
    1541:	w4 >>= 0x10
    1542:	w5 = w1
    1543:	w5 <<= 0x10
    1544:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1545:	w3 += w2
    1546:	w2 -= w1
    1547:	w2 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1548:	w4 = w2
    1549:	w4 >>= 0xd
    1550:	w5 = w2
    1551:	w5 <<= 0x13
    1552:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1553:	w1 += w3
    1554:	w3 -= w2
    1555:	w3 ^= w5
    1556:	w2 += w1
    1557:	w4 = w3
    1558:	w4 += w2
; 	return (word << shift) | (word >> ((-shift) & 31));
    1559:	w5 = w4
    1560:	w5 >>= 0x12
    1561:	w6 = w4
    1562:	w6 <<= 0xe
    1563:	w6 |= w5
    1564:	w5 = w3
    1565:	w5 >>= 0x1c
; 	__jhash_mix(a, b, c);
    1566:	w1 -= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1567:	w3 <<= 0x4
    1568:	w3 |= w5
; 	__jhash_mix(a, b, c);
    1569:	w1 ^= w3
; 	__jhash_final(a, b, c);
    1570:	w1 ^= w4
    1571:	w1 -= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1572:	w3 = w1
    1573:	w3 >>= 0x15
    1574:	w5 = w1
    1575:	w5 <<= 0xb
    1576:	w5 |= w3
; 	a += HASH_INIT6_SEED;
    1577:	w2 += 0xeb9f
; 	__jhash_final(a, b, c);
    1578:	w3 = w1
    1579:	w3 ^= w2
    1580:	w3 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1581:	w2 = w3
    1582:	w2 >>= 0x7
    1583:	w5 = w3
    1584:	w5 <<= 0x19
    1585:	w5 |= w2
; 	__jhash_final(a, b, c);
    1586:	w2 = w3
    1587:	w2 ^= w4
    1588:	w2 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1589:	w4 = w2
    1590:	w4 >>= 0x10
    1591:	w5 = w2
    1592:	w5 <<= 0x10
    1593:	w5 |= w4
; 	__jhash_final(a, b, c);
    1594:	w4 = w2
    1595:	w4 ^= w1
    1596:	w4 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1597:	w1 = w4
    1598:	w1 >>= 0x1c
    1599:	w5 = w4
    1600:	w5 <<= 0x4
    1601:	w5 |= w1
; 	__jhash_final(a, b, c);
    1602:	w1 = w4
    1603:	w1 ^= w3
    1604:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1605:	w3 = w1
    1606:	w3 >>= 0x12
    1607:	w5 = w1
    1608:	w5 <<= 0xe
    1609:	w5 |= w3
; 	__jhash_final(a, b, c);
    1610:	w1 ^= w2
    1611:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1612:	w2 = w1
    1613:	w2 >>= 0x8
    1614:	w3 = w1
    1615:	w3 <<= 0x18
    1616:	w3 |= w2
; 	__jhash_final(a, b, c);
    1617:	w1 ^= w4
    1618:	w1 -= w3
; 	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
    1619:	w1 %= 0x7fed
    1620:	*(u32 *)(r10 - 0x10) = w1
; 	asm volatile("%[index] <<= 2\n\t"
    1621:	r1 <<= 0x2
    1622:	if r1 > 0x1ffb0 goto +0x1 <LBB16_113+0x600>
    1623:	r0 += r1
    1624:	w8 = *(u32 *)(r0 + 0x0)

00000000000032c8 <LBB16_119>:
    1625:	r6 = *(u64 *)(r10 - 0x98)
    1626:	goto +0xd <LBB16_122>

00000000000032d8 <LBB16_120>:
; 	__u16 slot = (get_prandom_u32() % svc->count) + 1;
    1627:	call 0x7
    1628:	w1 = *(u16 *)(r7 + 0x4)
    1629:	w0 %= w1
    1630:	w0 += 0x1
; 	key->backend_slot = slot;
    1631:	*(u16 *)(r10 - 0x76) = w0
    1632:	r2 = r10
    1633:	r2 += -0x88
; 	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
    1634:	r1 = 0x0 ll
    1636:	call 0x1
    1637:	w8 = 0x0
; 	return be ? be->backend_id : 0;
    1638:	if r0 == 0x0 goto +0x1 <LBB16_122>
    1639:	w8 = *(u32 *)(r0 + 0x0)

0000000000003340 <LBB16_122>:
    1640:	*(u32 *)(r10 - 0x48) = w8
    1641:	r2 = r10
    1642:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1643:	r1 = 0x0 ll
    1645:	call 0x1
    1646:	r3 = r8
    1647:	w1 = 0x0
; 			if (backend == NULL)
    1648:	*(u32 *)(r10 - 0xa0) = w1
    1649:	if r0 == 0x0 goto +0x107 <LBB16_169>

0000000000003390 <LBB16_123>:
    1650:	r1 = 0x0
; 	struct ct_entry entry = { };
    1651:	*(u64 *)(r10 - 0x28) = r1
    1652:	*(u64 *)(r10 - 0x20) = r1
    1653:	*(u64 *)(r10 - 0x18) = r1
    1654:	*(u64 *)(r10 - 0x30) = r1
    1655:	*(u64 *)(r10 - 0x38) = r1
    1656:	*(u64 *)(r10 - 0x48) = r1
; 	entry->rev_nat_index = state->rev_nat_index;
    1657:	w1 = *(u32 *)(r10 - 0xc0)
    1658:	*(u16 *)(r10 - 0x22) = w1
; 		entry->backend_id = state->backend_id;
    1659:	w1 = w3
    1660:	*(u64 *)(r10 - 0x40) = r1
    1661:	w1 = 0x0
; 	entry->src_sec_id = state->src_sec_id;
    1662:	*(u32 *)(r10 - 0x1c) = w1
    1663:	w7 = 0x1
; 	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
    1664:	w1 = *(u8 *)(r10 - 0x4c)
    1665:	if w1 == 0x6 goto +0x1 <LBB16_125>
    1666:	w7 = 0x0

0000000000003418 <LBB16_125>:
    1667:	w8 = 0x3c
; 	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
    1668:	w7 <<= 0x9
; 	if (tcp) {
    1669:	if w1 != 0x6 goto +0xb <LBB16_129>
; 		entry->seen_non_syn |= !syn;
    1670:	w2 = w7
    1671:	w2 &= 0xffe0
    1672:	w2 >>= 0x5
    1673:	w2 ^= 0x10
    1674:	w1 = *(u16 *)(r10 - 0x24)
    1675:	w1 |= w2
; 		if (entry->seen_non_syn) {
    1676:	w2 = w1
    1677:	w2 &= 0x10
    1678:	if w2 == 0x0 goto +0x1 <LBB16_128>
    1679:	w8 = 0x5460

0000000000003480 <LBB16_128>:
; 		entry->seen_non_syn |= !syn;
    1680:	*(u16 *)(r10 - 0x24) = w1

0000000000003488 <LBB16_129>:
    1681:	*(u64 *)(r10 - 0xd8) = r0
    1682:	*(u64 *)(r10 - 0xf0) = r3
; 	__u32 now = (__u32)bpf_mono_now();
    1683:	call 0x5
    1684:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    1685:	w8 += w0
    1686:	*(u32 *)(r10 - 0x28) = w8
; 	barrier();
    1687:	w7 >>= 0x8
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1688:	w2 = *(u8 *)(r10 - 0x1e)
; 	seen_flags |= accumulated_flags;
    1689:	w1 = w2
    1690:	w1 |= w7
; 		last_report = READ_ONCE(entry->last_tx_report);
    1691:	w3 = *(u32 *)(r10 - 0x18)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1692:	w3 += 0x5
    1693:	if w3 < w0 goto +0x3 <LBB16_131>
    1694:	w3 = w1
    1695:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1696:	if w2 == w3 goto +0x2 <LBB16_132>

0000000000003508 <LBB16_131>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    1697:	*(u8 *)(r10 - 0x1e) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    1698:	*(u32 *)(r10 - 0x18) = w0

0000000000003518 <LBB16_132>:
    1699:	r1 = 0x1
; 	entry.packets = 1;
    1700:	*(u64 *)(r10 - 0x38) = r1
; 	return ctx->len;
    1701:	w1 = *(u32 *)(r6 + 0x0)
; 	entry.bytes = ctx_full_len(ctx);
    1702:	*(u64 *)(r10 - 0x30) = r1
    1703:	r2 = r10
; 	entry.packets = 1;
    1704:	r2 += -0x70
    1705:	r3 = r10
    1706:	r3 += -0x48
    1707:	w1 = 0x0
; 	err = map_update_elem(map_main, tuple, &entry, 0);
    1708:	*(u32 *)(r10 - 0xa0) = w1
    1709:	r1 = *(u64 *)(r10 - 0xd0)
    1710:	w4 = 0x0
    1711:	call 0x2
    1712:	w7 = w0
    1713:	w9 = 0x0
; 	if (unlikely(err < 0))
    1714:	if w7 s> -0x1 goto +0xe <LBB16_134>
    1715:	w1 = 0x1
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    1716:	*(u32 *)(r10 - 0xc) = w1
    1717:	*(u32 *)(r10 - 0x10) = w1
    1718:	r4 = r10
    1719:	r4 += -0x10
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    1720:	r1 = r6
    1721:	r2 = 0x0 ll
    1723:	r3 = 0xffffffff ll
    1725:	w5 = 0x8
    1726:	call 0x19
    1727:	w9 = -0x9b
    1728:	*(u32 *)(r10 - 0xa0) = w7

0000000000003608 <LBB16_134>:
    1729:	r2 = *(u64 *)(r10 - 0xf0)
    1730:	r3 = *(u64 *)(r10 - 0xd8)
; 		if (IS_ERR(ret))
    1731:	if w7 s< 0x0 goto +0xb5 <LBB16_169>

0000000000003620 <LBB16_149>:
; 	tuple->flags = flags;
    1732:	w1 = *(u32 *)(r10 - 0xc8)
    1733:	*(u8 *)(r10 - 0x4b) = w1
    1734:	r7 = *(u64 *)(r10 - 0xb8)
; 	return svc->flags & SVC_FLAG_AFFINITY;
    1735:	w1 = *(u8 *)(r7 + 0x8)
    1736:	w1 &= 0x10
; 	if (lb6_svc_is_affinity(svc))
    1737:	*(u64 *)(r10 - 0xd8) = r3
    1738:	if w1 == 0x0 goto +0x1f <LBB16_151>
    1739:	r9 = r2
; 	__u32 now = (__u32)bpf_mono_now();
    1740:	call 0x5
    1741:	r1 = 0x0
; 	struct lb6_affinity_key key = {
    1742:	*(u64 *)(r10 - 0x38) = r1
    1743:	*(u64 *)(r10 - 0x40) = r1
    1744:	*(u64 *)(r10 - 0x48) = r1
; 		.rev_nat_id	= svc->rev_nat_index,
    1745:	w1 = *(u16 *)(r7 + 0x6)
; 	struct lb6_affinity_key key = {
    1746:	*(u16 *)(r10 - 0x38) = w1
    1747:	w1 = *(u8 *)(r10 - 0x36)
    1748:	w1 &= 0xfe
    1749:	*(u8 *)(r10 - 0x36) = w1
; 	dst->d2 = src->d2;
    1750:	r1 = *(u64 *)(r10 - 0xe8)
    1751:	*(u64 *)(r10 - 0x40) = r1
; 	dst->d1 = src->d1;
    1752:	r1 = *(u64 *)(r10 - 0xe0)
    1753:	*(u64 *)(r10 - 0x48) = r1
; 	struct lb_affinity_val val = {
    1754:	*(u32 *)(r10 - 0x8) = w9
; 	__u32 now = (__u32)bpf_mono_now();
    1755:	r0 /= 0x3b9aca00
; 		.last_used	= now,
    1756:	r0 <<= 0x20
    1757:	r0 >>= 0x20
; 	struct lb_affinity_val val = {
    1758:	*(u64 *)(r10 - 0x10) = r0
    1759:	w1 = 0x0
    1760:	*(u32 *)(r10 - 0x4) = w1
    1761:	r2 = r10
    1762:	r2 += -0x48
    1763:	r3 = r10
    1764:	r3 += -0x10
; 	map_update_elem(&LB6_AFFINITY_MAP, &key, &val, 0);
    1765:	r1 = 0x0 ll
    1767:	w4 = 0x0
    1768:	call 0x2
    1769:	r3 = *(u64 *)(r10 - 0xd8)

0000000000003750 <LBB16_151>:
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1770:	r1 = *(u64 *)(r3 + 0x8)
    1771:	*(u64 *)(r10 - 0x68) = r1
; 	case  8: jmp_8:  __it_mob(d, s, 64);
    1772:	r1 = *(u64 *)(r3 + 0x0)
    1773:	*(u64 *)(r10 - 0x70) = r1
; 	if (likely(backend->port))
    1774:	w1 = *(u16 *)(r3 + 0x10)
    1775:	if w1 == 0x0 goto +0x1 <LBB16_153>
; 		tuple->sport = backend->port;
    1776:	*(u16 *)(r10 - 0x4e) = w1

0000000000003788 <LBB16_153>:
; 	return lb6_xlate(ctx, tuple->nexthdr, l3_off, l4_off, key, backend);
    1777:	w1 = *(u8 *)(r10 - 0x4c)
; 	switch (nexthdr) {
    1778:	if w1 == 0x3a goto +0x9 <LBB16_158>
    1779:	if w1 == 0x11 goto +0xd <LBB16_157>
    1780:	w7 = 0x1
    1781:	w8 = 0x0
    1782:	w2 = 0x0
; 	switch (nexthdr) {
    1783:	*(u32 *)(r10 - 0xc8) = w2
    1784:	if w1 != 0x6 goto +0xc <LBB16_160>
    1785:	w1 = 0x10
    1786:	*(u32 *)(r10 - 0xc8) = w1
    1787:	goto +0x3 <LBB16_159>

00000000000037e0 <LBB16_158>:
    1788:	w1 = 0x2
    1789:	*(u32 *)(r10 - 0xc8) = w1
    1790:	w8 = 0x0

00000000000037f8 <LBB16_159>:
    1791:	w7 = 0x0
    1792:	goto +0x4 <LBB16_160>

0000000000003808 <LBB16_157>:
    1793:	w1 = 0x6
    1794:	*(u32 *)(r10 - 0xc8) = w1
    1795:	w7 = 0x0
    1796:	w8 = 0x20

0000000000003828 <LBB16_160>:
; 	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
    1797:	r1 = r6
    1798:	w2 = 0x18
    1799:	w4 = 0x10
    1800:	w5 = 0x0
    1801:	call 0x9
    1802:	w9 = -0x8d
; 	if (ipv6_store_daddr(ctx, new_dst->addr, l3_off) < 0)
    1803:	if w0 s< 0x0 goto +0x6f <LBB16_170>
; 	if (csum_off.offset) {
    1804:	if w7 != 0x0 goto +0x12 <LBB16_163>
    1805:	r1 = r10
    1806:	r1 += -0x88
; 	return csum_diff_external(from, size_from, to, size_to, seed);
    1807:	w2 = 0x10
    1808:	r3 = *(u64 *)(r10 - 0xd8)
    1809:	w4 = 0x10
    1810:	w5 = 0x0
    1811:	call 0x1c
; 	return l4_csum_replace(ctx, (__u32)(l4_off + csum->offset), from, to, flags | csum->flags);
    1812:	w2 = *(u32 *)(r10 - 0xc8)
    1813:	w1 = *(u32 *)(r10 - 0xb0)
    1814:	w2 += w1
    1815:	w5 = w8
    1816:	w5 |= 0x10
    1817:	r1 = r6
    1818:	w3 = 0x0
    1819:	w4 = w0
    1820:	call 0xb
    1821:	w9 = -0x9a
    1822:	if w0 s< 0x0 goto +0x5c <LBB16_170>

00000000000038f8 <LBB16_163>:
; 			   backend->port);
    1823:	r1 = *(u64 *)(r10 - 0xd8)
    1824:	w4 = *(u16 *)(r1 + 0x10)
; 	if (likely(backend_port) && dport != backend_port) {
    1825:	if w4 == 0x0 goto +0x18 <LBB16_168>
    1826:	w3 = *(u16 *)(r10 - 0x78)
; 	if (likely(backend_port) && dport != backend_port) {
    1827:	if w3 == w4 goto +0x16 <LBB16_168>
    1828:	*(u16 *)(r10 - 0x48) = w4
    1829:	w7 = *(u32 *)(r10 - 0xb0)
    1830:	w2 = *(u32 *)(r10 - 0xc8)
; 	return l4_csum_replace(ctx, (__u32)(l4_off + csum->offset), from, to, flags | csum->flags);
    1831:	w2 += w7
    1832:	w8 |= 0x2
    1833:	r1 = r6
    1834:	w5 = w8
    1835:	call 0xb
    1836:	w9 = -0x9a
; 	if (csum_l4_replace(ctx, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    1837:	if w0 s< 0x0 goto +0xb <LBB16_167>
; 	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
    1838:	w2 = w7
    1839:	w2 += 0x2
    1840:	r3 = r10
    1841:	r3 += -0x48
    1842:	r1 = r6
    1843:	w4 = 0x2
    1844:	w5 = 0x0
    1845:	call 0x9
    1846:	w9 = w0
    1847:	w9 s>>= 0x1f
    1848:	w9 &= -0x8d

00000000000039c8 <LBB16_167>:
    1849:	if w9 s< 0x0 goto +0x41 <LBB16_170>

00000000000039d0 <LBB16_168>:
    1850:	w9 = 0x0
    1851:	goto +0x3f <LBB16_170>

00000000000039e0 <LBB16_300>:
; 		new_entry.bytes = bytes;
    1852:	*(u64 *)(r10 - 0x40) = r6
    1853:	r1 = 0x1
; 		new_entry.count = 1;
    1854:	*(u64 *)(r10 - 0x48) = r1
    1855:	r2 = r10
    1856:	r2 += -0x70
    1857:	r3 = r10
    1858:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
    1859:	r1 = 0x0 ll
    1861:	w4 = 0x0
    1862:	call 0x2

0000000000003a38 <LBB16_301>:
; 	tail_call_static(ctx, CALLS_MAP, index);
    1863:	r1 = r7
    1864:	r2 = 0x0 ll
    1866:	r3 = 0x1
    1867:	call 0xc
    1868:	w9 = 0x2

0000000000003a68 <LBB16_302>:
; }
    1869:	w0 = w9
    1870:	exit

0000000000003a78 <LBB16_144>:
; 	__u16 slot = (get_prandom_u32() % svc->count) + 1;
    1871:	call 0x7
    1872:	r1 = *(u64 *)(r10 - 0xb8)
    1873:	w1 = *(u16 *)(r1 + 0x4)
    1874:	w0 %= w1
    1875:	w0 += 0x1
; 	key->backend_slot = slot;
    1876:	*(u16 *)(r10 - 0x76) = w0
    1877:	r2 = r10
    1878:	r2 += -0x88
; 	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
    1879:	r1 = 0x0 ll
    1881:	call 0x1
; 	return be ? be->backend_id : 0;
    1882:	if r0 == 0x0 goto +0x1 <LBB16_146>
    1883:	w7 = *(u32 *)(r0 + 0x0)

0000000000003ae0 <LBB16_146>:
    1884:	r1 = r7
    1885:	*(u32 *)(r10 - 0x48) = w1
    1886:	r2 = r10
    1887:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1888:	r1 = 0x0 ll
    1890:	call 0x1
    1891:	w1 = 0x0
    1892:	*(u32 *)(r10 - 0xa0) = w1
    1893:	r6 = *(u64 *)(r10 - 0x98)
; 			if (!backend)
    1894:	if r0 == 0x0 goto +0x12 <LBB16_169>
; 			state->rev_nat_index = svc->rev_nat_index;
    1895:	r1 = *(u64 *)(r10 - 0xb8)
    1896:	w1 = *(u16 *)(r1 + 0x6)
; 	entry = map_lookup_elem(map, tuple);
    1897:	*(u32 *)(r10 - 0xc0) = w1
    1898:	r2 = r10
; 			state->rev_nat_index = svc->rev_nat_index;
    1899:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
    1900:	r1 = *(u64 *)(r10 - 0xd0)
    1901:	r8 = r0
    1902:	call 0x1
    1903:	r3 = r8
    1904:	r2 = r7
    1905:	w1 = 0x0
; 	if (!entry)
    1906:	*(u32 *)(r10 - 0xa0) = w1
    1907:	if r0 == 0x0 goto -0xb0 <LBB16_149>
; 	entry->rev_nat_index = rev_nat_index;
    1908:	w1 = *(u32 *)(r10 - 0xc0)
    1909:	*(u16 *)(r0 + 0x26) = w1
; 	entry->backend_id = backend_id;
    1910:	w1 = w2
    1911:	*(u64 *)(r0 + 0x8) = r1
    1912:	goto -0xb5 <LBB16_149>

0000000000003bc8 <LBB16_169>:
; 	tuple->flags = flags;
    1913:	w1 = *(u32 *)(r10 - 0xc8)
    1914:	*(u8 *)(r10 - 0x4b) = w1

0000000000003bd8 <LBB16_170>:
    1915:	r7 = *(u64 *)(r10 - 0xb8)
; 	if (IS_ERR(ret))
    1916:	if w9 s< 0x0 goto -0x62d <LBB16_245>
    1917:	if w9 == 0x2 goto -0x62e <LBB16_245>
    1918:	w1 = 0x0
; 	struct endpoint_key key = {};
    1919:	*(u32 *)(r10 - 0x38) = w1
; 	key.ip6 = *ip6;
    1920:	r1 = *(u64 *)(r10 - 0x70)
    1921:	*(u64 *)(r10 - 0x48) = r1
    1922:	r1 = *(u64 *)(r10 - 0x68)
    1923:	*(u64 *)(r10 - 0x40) = r1
    1924:	w1 = 0x2
; 	key.family = ENDPOINT_KEY_IPV6;
    1925:	*(u8 *)(r10 - 0x38) = w1
    1926:	r2 = r10
    1927:	r2 += -0x48
; 	return map_lookup_elem(&ENDPOINTS_MAP, &key);
    1928:	r1 = 0x0 ll
    1930:	call 0x1
; 	if (!backend_local && lb6_svc_is_hostport(svc))
    1931:	if r0 != 0x0 goto +0x6 <LBB16_175>
    1932:	w9 = -0x86
; 	return svc->flags & SVC_FLAG_HOSTPORT;
    1933:	w1 = *(u8 *)(r7 + 0x8)
    1934:	w1 &= 0x8
; 	if (!backend_local && lb6_svc_is_hostport(svc))
    1935:	if w1 != 0x0 goto -0x640 <LBB16_245>
; 				 tuple->nexthdr);
    1936:	w1 = *(u8 *)(r10 - 0x4c)
; 	if (backend_local || !nodeport_uses_dsr6(svc, tuple)) {
    1937:	if w1 == 0x6 goto +0x167 <LBB16_240>

0000000000003c90 <LBB16_175>:
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1938:	r1 = *(u64 *)(r10 - 0x58)
    1939:	r2 = *(u64 *)(r10 - 0x68)
    1940:	*(u64 *)(r10 - 0x58) = r2
; 	case  8: jmp_8:  __it_mob(d, s, 64);
    1941:	r2 = *(u64 *)(r10 - 0x70)
    1942:	r3 = *(u64 *)(r10 - 0x60)
    1943:	*(u64 *)(r10 - 0x70) = r3
    1944:	*(u64 *)(r10 - 0x60) = r2
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1945:	*(u64 *)(r10 - 0x68) = r1
; 	tmp = tuple->sport;
    1946:	w1 = *(u16 *)(r10 - 0x4e)
; 	tuple->sport = tuple->dport;
    1947:	w2 = *(u16 *)(r10 - 0x50)
    1948:	*(u16 *)(r10 - 0x4e) = w2
; 	tuple->dport = tmp;
    1949:	*(u16 *)(r10 - 0x50) = w1
    1950:	r7 = 0x0 ll
; 	if (tuple->nexthdr == IPPROTO_TCP)
    1952:	w2 = *(u8 *)(r10 - 0x4c)
    1953:	if w2 == 0x6 goto +0x2 <LBB16_177>
    1954:	r7 = 0x0 ll

0000000000003d20 <LBB16_177>:
    1956:	*(u64 *)(r10 - 0xb8) = r0
    1957:	w1 = 0x0
; 	tuple->flags = ct_lookup_select_tuple_type(dir, scope);
    1958:	*(u8 *)(r10 - 0x4b) = w1
; 	union tcp_flags tcp_flags = { .value = 0 };
    1959:	*(u32 *)(r10 - 0x48) = w1
    1960:	w9 = 0x0
    1961:	*(u32 *)(r10 - 0xc8) = w2
; 	if (is_tcp) {
    1962:	if w2 != 0x6 goto +0x12 <LBB16_181>
    1963:	w2 = *(u32 *)(r10 - 0xb0)
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
    1964:	w2 += 0xc
    1965:	r3 = r10
    1966:	r3 += -0x48
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
    1967:	r1 = r6
    1968:	w4 = 0x2
    1969:	call 0x1a
    1970:	w2 = -0x87
    1971:	w3 = 0x1
    1972:	w8 = 0x0
; 		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
    1973:	if w0 s< 0x0 goto +0xa5 <LBB16_209>
; 		action = ct_tcp_select_action(tcp_flags);
    1974:	w9 = *(u32 *)(r10 - 0x48)
; 	if (unlikely(flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
    1975:	w1 = w9
    1976:	w1 &= 0x500
    1977:	w9 >>= 0x9
    1978:	w9 &= 0x1
    1979:	if w1 == 0x0 goto +0x1 <LBB16_181>
    1980:	w9 = 0x2

0000000000003de8 <LBB16_181>:
; 		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_entry_types,
    1981:	w1 = *(u32 *)(r10 - 0x48)
; 	entry = map_lookup_elem(map, tuple);
    1982:	*(u32 *)(r10 - 0xb0) = w1
    1983:	r2 = r10
    1984:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
    1985:	r1 = r7
    1986:	call 0x1
    1987:	r7 = r0
    1988:	w8 = 0x0
    1989:	w3 = 0x0
    1990:	w2 = 0x0
; 	if (entry) {
    1991:	if r7 == 0x0 goto +0x93 <LBB16_209>
; 	    entry->node_port && entry->rev_nat_index) {
    1992:	w1 = *(u16 *)(r7 + 0x24)
    1993:	w4 = w1
    1994:	w4 &= 0x20
    1995:	if w4 == 0x0 goto +0x8f <LBB16_209>
    1996:	w4 = *(u16 *)(r7 + 0x26)
; 	if ((ct_entry_types & CT_ENTRY_NODEPORT) &&
    1997:	if w4 == 0x0 goto +0x8d <LBB16_209>
; 		if (!state || !state->rev_nat_index)
    1998:	w5 = *(u32 *)(r10 - 0xc0)
    1999:	w5 &= 0xffff
    2000:	if w5 == 0x0 goto +0x1 <LBB16_186>
; 		if (entry->rev_nat_index == state->rev_nat_index)
    2001:	if w4 != w5 goto +0x89 <LBB16_209>

0000000000003e90 <LBB16_186>:
; 	return !entry->rx_closing || !entry->tx_closing;
    2002:	w2 = w1
    2003:	w2 &= 0x3
    2004:	w8 = *(u32 *)(r10 - 0xb0)
; 		if (ct_entry_alive(entry))
    2005:	if w2 == 0x3 goto +0x20 <LBB16_193>
    2006:	w3 = 0x3c
; 	if (tcp) {
    2007:	w2 = *(u32 *)(r10 - 0xc8)
    2008:	if w2 != 0x6 goto +0x9 <LBB16_190>
; 		entry->seen_non_syn |= !syn;
    2009:	w2 = w8
    2010:	w2 ^= -0x1
    2011:	w2 >>= 0x5
    2012:	w2 &= 0x10
    2013:	w1 |= w2
    2014:	*(u16 *)(r7 + 0x24) = w1
; 		if (entry->seen_non_syn) {
    2015:	w1 &= 0x10
    2016:	if w1 == 0x0 goto +0x1 <LBB16_190>
    2017:	w3 = 0x5460

0000000000003f10 <LBB16_190>:
    2018:	w8 = w3
; 	__u32 now = (__u32)bpf_mono_now();
    2019:	call 0x5
    2020:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2021:	w8 += w0
    2022:	*(u32 *)(r7 + 0x20) = w8
    2023:	w8 = *(u32 *)(r10 - 0xb0)
; 	barrier();
    2024:	w3 = w8
    2025:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2026:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2027:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2028:	w1 = w2
    2029:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    2030:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2031:	w3 += 0x5
    2032:	if w3 < w0 goto +0x3 <LBB16_192>
    2033:	w3 = w1
    2034:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2035:	if w2 == w3 goto +0x2 <LBB16_193>

0000000000003fa0 <LBB16_192>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2036:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2037:	*(u32 *)(r7 + 0x30) = w0

0000000000003fb0 <LBB16_193>:
    2038:	r1 = 0x1
; 		__sync_fetch_and_add(&entry->packets, 1);
    2039:	lock *(u64 *)(r7 + 0x10) += r1
; 	return ctx->len;
    2040:	w1 = *(u32 *)(r6 + 0x0)
; 		__sync_fetch_and_add(&entry->bytes, ctx_full_len(ctx));
    2041:	lock *(u64 *)(r7 + 0x18) += r1
; 		switch (action) {
    2042:	if w9 == 0x2 goto +0x2f <LBB16_202>
    2043:	w4 = 0x0
; 		switch (action) {
    2044:	if w9 != 0x1 goto +0x4b <LBB16_208>
; 	return entry->tx_closing || entry->rx_closing;
    2045:	w1 = *(u16 *)(r7 + 0x24)
    2046:	w2 = w1
    2047:	w2 &= 0x3
; 			if (unlikely(ct_entry_closing(entry))) {
    2048:	if w2 == 0x0 goto +0x47 <LBB16_208>
    2049:	w2 = 0x0
; 	entry->tx_flags_seen = 0;
    2050:	*(u16 *)(r7 + 0x2a) = w2
; 				entry->seen_non_syn = false;
    2051:	w1 &= 0xffec
    2052:	*(u16 *)(r7 + 0x24) = w1
    2053:	w9 = 0x3c
; 	if (tcp) {
    2054:	w2 = *(u32 *)(r10 - 0xc8)
    2055:	if w2 != 0x6 goto +0x8 <LBB16_199>
; 		entry->seen_non_syn |= !syn;
    2056:	w2 = *(u32 *)(r10 - 0xb0)
    2057:	w2 ^= -0x1
    2058:	w2 >>= 0x5
    2059:	w2 &= 0x10
    2060:	w1 |= w2
    2061:	*(u16 *)(r7 + 0x24) = w1
    2062:	if w2 == 0x0 goto +0x1 <LBB16_199>
    2063:	w9 = 0x5460

0000000000004080 <LBB16_199>:
; 	__u32 now = (__u32)bpf_mono_now();
    2064:	call 0x5
    2065:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2066:	w9 += w0
    2067:	*(u32 *)(r7 + 0x20) = w9
; 	barrier();
    2068:	w3 = *(u32 *)(r10 - 0xb0)
    2069:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2070:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2071:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2072:	w1 = w2
    2073:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    2074:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2075:	w3 += 0x5
    2076:	r6 = *(u64 *)(r10 - 0x98)
    2077:	w8 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2078:	if w3 < w0 goto +0x6 <LBB16_201>
    2079:	w4 = w1
    2080:	w4 &= 0xff
    2081:	r5 = r2
    2082:	w3 = 0x0
    2083:	w2 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2084:	if w5 == w4 goto +0x36 <LBB16_209>

0000000000004128 <LBB16_201>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2085:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2086:	*(u32 *)(r7 + 0x30) = w0
; 	barrier();
    2087:	w3 = 0x0
    2088:	w2 = 0x0
    2089:	goto +0x31 <LBB16_209>

0000000000004150 <LBB16_202>:
; 				    (seen_flags.value & TCP_FLAG_RST)) {
    2090:	w2 = w8
    2091:	w2 &= 0x400
    2092:	w1 = 0x2
; 				if (!ct_entry_seen_both_syns(entry) &&
    2093:	if w2 == 0x0 goto +0x1 <LBB16_204>
    2094:	w1 = 0x3

0000000000004178 <LBB16_204>:
    2095:	w2 = *(u16 *)(r7 + 0x24)
; 				if (!ct_entry_seen_both_syns(entry) &&
    2096:	w2 |= w1
    2097:	*(u16 *)(r7 + 0x24) = w2
    2098:	w4 = 0x100
; 	return !entry->rx_closing || !entry->tx_closing;
    2099:	w2 &= 0x3
; 			if (ct_entry_alive(entry))
    2100:	if w2 != 0x3 goto +0x13 <LBB16_208>
; 	__u32 now = (__u32)bpf_mono_now();
    2101:	call 0x5
    2102:	w4 = 0x100
; 	__u32 now = (__u32)bpf_mono_now();
    2103:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2104:	w1 = w0
    2105:	w1 += 0xa
    2106:	*(u32 *)(r7 + 0x20) = w1
; 	barrier();
    2107:	w8 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2108:	w8 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2109:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2110:	w1 = w2
    2111:	w1 |= w8
; 		last_report = READ_ONCE(entry->last_tx_report);
    2112:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2113:	w3 += 0x5
    2114:	if w3 < w0 goto +0x3 <LBB16_207>
    2115:	w3 = w1
    2116:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2117:	if w2 == w3 goto +0x2 <LBB16_208>

0000000000004230 <LBB16_207>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2118:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2119:	*(u32 *)(r7 + 0x30) = w0

0000000000004240 <LBB16_208>:
; 		state->loopback = entry->lb_loopback;
    2120:	w2 = *(u16 *)(r7 + 0x24)
    2121:	w1 = w2
    2122:	w1 >>= 0x3
    2123:	w8 = w1
    2124:	w8 &= 0x1
    2125:	w8 |= w4
; 		state->dsr_internal = entry->dsr_internal;
    2126:	w3 = w2
    2127:	w3 >>= 0x5
    2128:	w3 &= 0x4
    2129:	w8 |= w3
; 		state->proxy_redirect = entry->proxy_redirect;
    2130:	w2 >>= 0x2
    2131:	w2 &= 0x10
; 		state->from_l7lb = entry->from_l7lb;
    2132:	w8 |= w2
; 		state->from_tunnel = entry->from_tunnel;
    2133:	w1 &= 0xa0
    2134:	w8 |= w1
    2135:	w2 = 0x1
    2136:	w3 = 0x0
; 	state->rev_nat_index = entry->rev_nat_index;
    2137:	w1 = *(u16 *)(r7 + 0x26)
    2138:	*(u32 *)(r10 - 0xc0) = w1

00000000000042d8 <LBB16_209>:
    2139:	w7 = 0x0
    2140:	w9 = w2
; 		if (ret < 0)
    2141:	if w3 != 0x0 goto +0x99 <LBB16_239>
; 		switch (ret) {
    2142:	if w2 == 0x1 goto +0x69 <LBB16_226>
    2143:	w9 = -0xa3
; 		switch (ret) {
    2144:	if w2 != 0x0 goto +0x96 <LBB16_239>
; 			ct_state.ifindex = (__u16)THIS_INTERFACE_IFINDEX;
    2145:	r1 = 0x0 ll
    2147:	w2 = *(u32 *)(r1 + 0x0)
; 	if (tuple->nexthdr == IPPROTO_TCP)
    2148:	w1 = *(u8 *)(r10 - 0x4c)
    2149:	r3 = 0x0
; 	struct ct_entry entry = { };
    2150:	*(u64 *)(r10 - 0x20) = r3
    2151:	*(u64 *)(r10 - 0x28) = r3
    2152:	*(u64 *)(r10 - 0x18) = r3
    2153:	*(u64 *)(r10 - 0x30) = r3
    2154:	*(u64 *)(r10 - 0x38) = r3
    2155:	*(u64 *)(r10 - 0x40) = r3
    2156:	*(u64 *)(r10 - 0x48) = r3
    2157:	w3 = 0xa
; 	entry->src_sec_id = state->src_sec_id;
    2158:	*(u32 *)(r10 - 0x1c) = w3
; 	entry->rev_nat_index = state->rev_nat_index;
    2159:	w3 = *(u32 *)(r10 - 0xc0)
    2160:	*(u16 *)(r10 - 0x22) = w3
; 		entry->ifindex = state->ifindex;
    2161:	*(u16 *)(r10 - 0x20) = w2
    2162:	r2 = 0x0 ll
    2164:	if w1 == 0x6 goto +0x2 <LBB16_214>
    2165:	r2 = 0x0 ll

00000000000043b8 <LBB16_214>:
    2167:	*(u64 *)(r10 - 0x98) = r2
; 		entry->proxy_redirect = state->proxy_redirect;
    2168:	w2 = w8
    2169:	w2 <<= 0x2
    2170:	w2 &= 0x40
; 		entry->lb_loopback = state->loopback;
    2171:	w3 = w8
    2172:	w3 <<= 0x3
; 		entry->from_l7lb = state->from_l7lb;
    2173:	w4 = w3
    2174:	w4 &= 0x100
; 		entry->proxy_redirect = state->proxy_redirect;
    2175:	w4 |= w2
; 		entry->from_tunnel = state->from_tunnel;
    2176:	w3 &= 0x408
; 		entry->dsr_internal = state->dsr_internal;
    2177:	w8 <<= 0x5
    2178:	w8 &= 0x80
; 		entry->from_tunnel = state->from_tunnel;
    2179:	w8 |= w3
; 		entry->lb_loopback = state->loopback;
    2180:	w2 = *(u16 *)(r10 - 0x24)
    2181:	w2 &= -0x5e9
; 		entry->from_tunnel = state->from_tunnel;
    2182:	w8 |= w2
    2183:	w8 |= w4
    2184:	w7 = 0x1
; 	if (tuple->nexthdr == IPPROTO_TCP)
    2185:	if w1 == 0x6 goto +0x1 <LBB16_216>
    2186:	w7 = 0x0

0000000000004458 <LBB16_216>:
    2187:	w9 = 0x3c
; 	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
    2188:	w7 <<= 0x9
; 		entry->from_l7lb = state->from_l7lb;
    2189:	w8 |= 0x20
    2190:	*(u16 *)(r10 - 0x24) = w8
; 	if (tcp) {
    2191:	if w1 != 0x6 goto +0xa <LBB16_220>
; 		entry->seen_non_syn |= !syn;
    2192:	w1 = w7
    2193:	w1 &= 0xffe0
    2194:	w1 >>= 0x5
    2195:	w1 ^= 0x10
    2196:	w8 |= w1
; 		if (entry->seen_non_syn) {
    2197:	w1 = w8
    2198:	w1 &= 0x10
    2199:	if w1 == 0x0 goto +0x1 <LBB16_219>
    2200:	w9 = 0x5460

00000000000044c8 <LBB16_219>:
; 		entry->seen_non_syn |= !syn;
    2201:	*(u16 *)(r10 - 0x24) = w8

00000000000044d0 <LBB16_220>:
; 	__u32 now = (__u32)bpf_mono_now();
    2202:	call 0x5
    2203:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2204:	w9 += w0
    2205:	*(u32 *)(r10 - 0x28) = w9
; 	barrier();
    2206:	w7 >>= 0x8
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2207:	w2 = *(u8 *)(r10 - 0x1e)
; 	seen_flags |= accumulated_flags;
    2208:	w1 = w2
    2209:	w1 |= w7
; 		last_report = READ_ONCE(entry->last_tx_report);
    2210:	w3 = *(u32 *)(r10 - 0x18)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2211:	w3 += 0x5
    2212:	if w3 < w0 goto +0x3 <LBB16_222>
    2213:	w3 = w1
    2214:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2215:	if w2 == w3 goto +0x2 <LBB16_223>

0000000000004540 <LBB16_222>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2216:	*(u8 *)(r10 - 0x1e) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2217:	*(u32 *)(r10 - 0x18) = w0

0000000000004550 <LBB16_223>:
    2218:	r1 = 0x1
; 	entry.packets = 1;
    2219:	*(u64 *)(r10 - 0x38) = r1
; 	return ctx->len;
    2220:	w1 = *(u32 *)(r6 + 0x0)
; 	entry.bytes = ctx_full_len(ctx);
    2221:	*(u64 *)(r10 - 0x30) = r1
    2222:	r2 = r10
; 	entry.packets = 1;
    2223:	r2 += -0x70
    2224:	r3 = r10
    2225:	r3 += -0x48
    2226:	w7 = 0x0
; 	err = map_update_elem(map_main, tuple, &entry, 0);
    2227:	r1 = *(u64 *)(r10 - 0x98)
    2228:	w4 = 0x0
    2229:	call 0x2
    2230:	w8 = w0
    2231:	w9 = 0x0
; 	if (unlikely(err < 0))
    2232:	if w8 s> -0x1 goto +0xe <LBB16_225>
    2233:	w1 = 0x1
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    2234:	*(u32 *)(r10 - 0xc) = w1
    2235:	*(u32 *)(r10 - 0x10) = w1
    2236:	r4 = r10
    2237:	r4 += -0x10
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    2238:	r1 = r6
    2239:	r2 = 0x0 ll
    2241:	r3 = 0xffffffff ll
    2243:	w5 = 0x8
    2244:	call 0x19
    2245:	w9 = -0x9b
    2246:	*(u32 *)(r10 - 0xa0) = w8

0000000000004638 <LBB16_225>:
; 			if (IS_ERR(ret))
    2247:	if w8 s< 0x0 goto +0x2f <LBB16_239>

0000000000004640 <LBB16_226>:
    2248:	r1 = 0x0
; 	union macaddr smac = {}, *mac;
    2249:	*(u64 *)(r10 - 0x48) = r1
; DEFINE_FUNC_CTX_POINTER(data_end)
    2250:	w1 = *(u32 *)(r6 + 0x50)
; DEFINE_FUNC_CTX_POINTER(data)
    2251:	w7 = *(u32 *)(r6 + 0x4c)
    2252:	w9 = -0x86
; 	if (data + tot_len > data_end)
    2253:	r2 = r7
    2254:	r2 += 0x28
; 	if (!revalidate_data(ctx, &data, &data_end, &ip6))
    2255:	if r2 > r1 goto +0x1f <LBB16_234>
    2256:	r3 = r10
    2257:	r3 += -0x48
; 	return ctx_load_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN);
    2258:	r1 = r6
    2259:	w2 = 0x6
    2260:	w4 = 0x6
    2261:	call 0x1a
; 	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
    2262:	if w0 s< 0x0 goto +0x18 <LBB16_234>
; 	mac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->saddr);
    2263:	r7 += 0x8
    2264:	r1 = 0x0 ll
    2266:	r2 = r7
    2267:	call 0x1
; 	if (!mac || eth_addrcmp(mac, &smac)) {
    2268:	if r0 == 0x0 goto +0x8 <LBB16_232>
; 	tmp = a->p1 - b->p1;
    2269:	w1 = *(u32 *)(r0 + 0x0)
    2270:	w2 = *(u32 *)(r10 - 0x48)
    2271:	w1 -= w2
; 	if (!tmp)
    2272:	if w1 != 0x0 goto +0x3 <LBB16_231>
; 		tmp = a->p2 - b->p2;
    2273:	w1 = *(u16 *)(r0 + 0x4)
    2274:	w2 = *(u16 *)(r10 - 0x44)
    2275:	w1 -= w2

0000000000004720 <LBB16_231>:
; 	if (!mac || eth_addrcmp(mac, &smac)) {
    2276:	if w1 == 0x0 goto +0x9 <LBB16_233>

0000000000004728 <LBB16_232>:
    2277:	r3 = r10
; 		int ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr,
    2278:	r3 += -0x48
    2279:	r1 = 0x0 ll
    2281:	r2 = r7
    2282:	w4 = 0x0
    2283:	call 0x2
    2284:	w9 = w0
    2285:	if w9 s< 0x0 goto +0x1 <LBB16_234>

0000000000004770 <LBB16_233>:
    2286:	w9 = 0x0

0000000000004778 <LBB16_234>:
    2287:	w7 = 0x1
; 		if (ret < 0)
    2288:	if w9 s> -0x1 goto +0x1 <LBB16_236>
    2289:	w7 = 0x0

0000000000004790 <LBB16_236>:
; 		if (ret < 0)
    2290:	r1 = *(u64 *)(r10 - 0xb8)
    2291:	if r1 == 0x0 goto +0x3 <LBB16_239>
    2292:	if w9 s< 0x0 goto +0x2 <LBB16_239>
    2293:	w7 = 0x0
    2294:	w9 = 0x0

00000000000047b8 <LBB16_239>:
    2295:	w7 &= 0x1
    2296:	if w7 == 0x0 goto -0x7a9 <LBB16_245>

00000000000047c8 <LBB16_240>:
    2297:	w1 = 0x0
; 	ctx->queue_mapping = aggregate;
    2298:	*(u32 *)(r6 + 0xc) = w1
; 				 tuple->nexthdr);
    2299:	w2 = *(u8 *)(r10 - 0x4c)
; 	if (nodeport_uses_dsr6(svc, tuple)) {
    2300:	if w2 != 0x6 goto +0x12 <LBB16_242>
; 		ctx_store_meta(ctx, CB_PORT, key->dport);
    2301:	w1 = *(u16 *)(r10 - 0x78)
; 	ctx->cb[off] = data;
    2302:	*(u32 *)(r6 + 0x30) = w1
; 	ctx_store_meta(ctx, off, addr->p1);
    2303:	w1 = *(u32 *)(r10 - 0x88)
; 	ctx->cb[off] = data;
    2304:	*(u32 *)(r6 + 0x34) = w1
; 	ctx_store_meta(ctx, off + 1, addr->p2);
    2305:	w1 = *(u32 *)(r10 - 0x84)
; 	ctx->cb[off] = data;
    2306:	*(u32 *)(r6 + 0x38) = w1
; 	ctx_store_meta(ctx, off + 2, addr->p3);
    2307:	w1 = *(u32 *)(r10 - 0x80)
; 	ctx->cb[off] = data;
    2308:	*(u32 *)(r6 + 0x3c) = w1
; 	ctx_store_meta(ctx, off + 3, addr->p4);
    2309:	w1 = *(u32 *)(r10 - 0x7c)
; 	ctx->cb[off] = data;
    2310:	*(u32 *)(r6 + 0x40) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
    2311:	r1 = r6
    2312:	r2 = 0x0 ll
    2314:	r3 = 0x15
    2315:	call 0xc
    2316:	w9 = -0x8c
    2317:	w1 = 0x15
    2318:	goto -0x7c0 <LBB16_244>

0000000000004878 <LBB16_242>:
; 	ctx->cb[off] = data;
    2319:	*(u32 *)(r6 + 0x34) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
    2320:	r1 = r6
    2321:	r2 = 0x0 ll
    2323:	r3 = 0x10
    2324:	call 0xc
    2325:	w9 = -0x8c
    2326:	w1 = 0x10
    2327:	goto -0x7c9 <LBB16_244>

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
      13:	if r2 > r1 goto +0x3cb <LBB16_296>
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
      20:	if w1 != 0x0 goto +0x142 <LBB16_247>
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
     131:	if r1 != 0x0 goto +0x384 <LBB16_27>
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
     163:	if w9 == -0x9f goto +0xa2 <LBB16_243>
     164:	w1 = 0x0
; 		if (ret == DROP_UNSUPP_SERVICE_PROTO) {
     165:	*(u32 *)(r10 - 0xa0) = w1
     166:	if w9 != -0x8e goto +0xab <LBB16_245>
     167:	*(u32 *)(r10 - 0xa0) = w1
     168:	w9 = 0x0
     169:	goto +0xa8 <LBB16_245>

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
     185:	if r7 == 0x0 goto +0x8c <LBB16_243>
     186:	*(u32 *)(r10 - 0xb0) = w8
; 	return svc->flags & SVC_FLAG_SOURCE_RANGE;
     187:	w1 = *(u8 *)(r7 + 0x8)
     188:	w1 <<= 0x18
     189:	w1 s>>= 0x18
; 	if (!lb6_svc_has_src_range_check(svc))
     190:	if w1 s> -0x1 goto +0x47 <LBB16_47>
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
     199:	*(u32 *)(r10 - 0xa0) = w3
     200:	*(u16 *)(r10 - 0x42) = w2
     201:	w2 = *(u8 *)(r1 + 0x0)
     202:	w4 = *(u8 *)(r1 + 0x1)
     203:	r4 <<= 0x8
     204:	r4 |= r2
     205:	w2 = *(u8 *)(r1 + 0x2)
     206:	r2 <<= 0x10
     207:	w3 = *(u8 *)(r1 + 0x3)
     208:	r3 <<= 0x18
     209:	r3 |= r2
     210:	r3 |= r4
     211:	w4 = *(u8 *)(r1 + 0x5)
     212:	w4 <<= 0x8
     213:	w2 = *(u8 *)(r1 + 0x4)
     214:	w4 |= w2
     215:	w5 = *(u8 *)(r1 + 0x6)
     216:	w5 <<= 0x10
     217:	w2 = *(u8 *)(r1 + 0x7)
     218:	w2 <<= 0x18
     219:	w2 |= w5
     220:	w2 |= w4
     221:	r2 <<= 0x20
     222:	r2 |= r3
     223:	w3 = *(u8 *)(r1 + 0x8)
     224:	w4 = *(u8 *)(r1 + 0x9)
     225:	r4 <<= 0x8
     226:	r4 |= r3
     227:	w5 = *(u8 *)(r1 + 0xa)
     228:	r5 <<= 0x10
     229:	w3 = *(u8 *)(r1 + 0xb)
     230:	r3 <<= 0x18
     231:	r3 |= r5
     232:	*(u64 *)(r10 - 0x40) = r2
     233:	r3 |= r4
     234:	w2 = *(u8 *)(r1 + 0xd)
     235:	w2 <<= 0x8
     236:	w4 = *(u8 *)(r1 + 0xc)
     237:	w2 |= w4
     238:	w4 = *(u8 *)(r1 + 0xe)
     239:	w4 <<= 0x10
     240:	w1 = *(u8 *)(r1 + 0xf)
     241:	w1 <<= 0x18
     242:	w1 |= w4
     243:	w1 |= w2
     244:	r1 <<= 0x20
     245:	r1 |= r3
     246:	*(u64 *)(r10 - 0x38) = r1
     247:	r2 = r10
     248:	r2 += -0x48
; 	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
     249:	r1 = 0x0 ll
     251:	call 0x1
     252:	w1 = 0x1
; 	if (map_lookup_elem(&LB6_SRC_RANGE_MAP, &key))
     253:	if r0 != 0x0 goto +0x1 <LBB16_46>
     254:	w1 = 0x0

00000000000007f8 <LBB16_46>:
; 	return verdict ^ !!(svc->flags2 & SVC_FLAG_SOURCE_RANGE_DENY);
     255:	w2 = *(u8 *)(r7 + 0x9)
     256:	w2 >>= 0x6
     257:	w1 ^= w2
     258:	w9 = -0xb1
; 	if (!lb6_src_range_ok(svc, (union v6addr *)&ip6->saddr))
     259:	w1 &= 0x1
     260:	if w1 != 0x0 goto +0x1 <LBB16_47>
     261:	goto +0x4c <LBB16_245>

0000000000000830 <LBB16_47>:
     262:	w9 = -0xae
     263:	w1 = 0x0
; 	return __lb_svc_is_routable(svc->flags);
     264:	*(u32 *)(r10 - 0xa0) = w1
     265:	w1 = *(u8 *)(r7 + 0x8)
; 	return (flags & SVC_FLAG_ROUTABLE) != 0;
     266:	w1 &= 0x40
; 	if (!lb6_svc_is_routable(svc))
     267:	if w1 == 0x0 goto +0x46 <LBB16_245>
; 	return svc->flags2 & SVC_FLAG_L7LOADBALANCER;
     268:	w1 = *(u8 *)(r7 + 0x9)
     269:	w1 &= 0x4
; 	if (lb6_svc_is_l7loadbalancer(svc) && svc->l7_lb_proxy_port > 0) {
     270:	if w1 == 0x0 goto +0x122 <LBB16_61>
     271:	w1 = *(u32 *)(r7 + 0x0)
     272:	if w1 == 0x0 goto +0x120 <LBB16_61>
; 				  THIS_INTERFACE_IFINDEX, TRACE_REASON_POLICY, monitor);
     273:	r2 = 0x0 ll
     275:	w2 = *(u32 *)(r2 + 0x0)
     276:	r2 = 0x568803a772ce ll
; 	union macaddr host_mac = HOST_IFINDEX_MAC;
     278:	*(u64 *)(r10 - 0x48) = r2
; 	union macaddr router_mac = THIS_INTERFACE_MAC;
     279:	r2 = 0x0 ll
     281:	w2 = *(u32 *)(r2 + 0x0)
     282:	*(u32 *)(r10 - 0x10) = w2
     283:	r2 = 0x0 ll
     285:	w2 = *(u32 *)(r2 + 0x0)
     286:	*(u16 *)(r10 - 0xc) = w2
; 		       MARK_MAGIC_TO_PROXY | (proxy_port << 16));
     287:	w1 <<= 0x10
     288:	w1 |= 0x200
; 	ctx->cb[off] = data;
     289:	*(u32 *)(r6 + 0x30) = w1
     290:	r3 = r10
     291:	r3 += -0x49
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     292:	r1 = r6
     293:	w2 = 0x7
     294:	w4 = 0x1
     295:	call 0x1a
     296:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     297:	if w0 s< 0x0 goto +0xf <LBB16_53>
     298:	w9 = -0xc4
; 	if (hl <= 1)
     299:	w1 = *(u8 *)(r10 - 0x49)
     300:	if w1 < 0x2 goto +0xc <LBB16_53>
; 	hl--;
     301:	w1 += -0x1
     302:	*(u8 *)(r10 - 0x49) = w1
     303:	r3 = r10
; 	hl--;
     304:	r3 += -0x49
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     305:	r1 = r6
     306:	w2 = 0x7
     307:	w4 = 0x1
     308:	w5 = 0x1
     309:	call 0x9
     310:	w9 = w0
     311:	w9 s>>= 0x1f
     312:	w9 &= -0x8d

00000000000009c8 <LBB16_53>:
; 	if (IS_ERR(ret)) {
     313:	if w9 s> -0x1 goto +0x199 <LBB16_56>
; 		if (ret == DROP_TTL_EXCEEDED)
     314:	if w9 != -0xc4 goto +0x1aa <LBB16_59>
     315:	w1 = 0x2
; 	ctx->cb[off] = data;
     316:	*(u32 *)(r6 + 0x34) = w1
     317:	w1 = 0x0
     318:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     319:	r1 = r6
     320:	r2 = 0x0 ll
     322:	r3 = 0x5
     323:	call 0xc
     324:	w9 = -0x8c
     325:	goto +0x19f <LBB16_59>

0000000000000a30 <LBB16_243>:
; 	ctx->cb[off] = data;
     326:	w1 = *(u32 *)(r10 - 0x90)
     327:	*(u32 *)(r6 + 0x30) = w1
     328:	w1 = 0x0
; 	ctx->cb[off] = data;
     329:	*(u32 *)(r6 + 0x34) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     330:	r1 = r6
     331:	r2 = 0x0 ll
     333:	r3 = 0x25
     334:	call 0xc
     335:	w9 = -0x8c
     336:	w1 = 0x25

0000000000000a88 <LBB16_244>:
     337:	*(u32 *)(r10 - 0xa0) = w1

0000000000000a90 <LBB16_245>:
     338:	r0 = *(u64 *)(r10 - 0xa8)
     339:	w7 = *(u32 *)(r10 - 0xa0)
; 		if (ret < 0 || ret == TC_ACT_REDIRECT)
     340:	if w9 s< 0x0 goto +0x284 <LBB16_296>
     341:	w8 = w9
; 		if (ret < 0 || ret == TC_ACT_REDIRECT)
     342:	if w9 == 0x7 goto +0x282 <LBB16_296>

0000000000000ab8 <LBB16_247>:
; DEFINE_FUNC_CTX_POINTER(data_end)
     343:	w1 = *(u32 *)(r6 + 0x50)
; DEFINE_FUNC_CTX_POINTER(data)
     344:	w3 = *(u32 *)(r6 + 0x4c)
; 	if (data + tot_len > data_end)
     345:	r2 = r3
     346:	r2 += 0x28
     347:	if r2 > r1 goto +0x1 <LBB16_249>
     348:	r0 = r3

0000000000000ae8 <LBB16_249>:
     349:	w9 = -0x86
; 	if (!revalidate_data(ctx, &data, &data_end, &ip6))
     350:	if r2 > r1 goto +0x27a <LBB16_296>
     351:	*(u32 *)(r10 - 0xa0) = w7
     352:	r1 = 0x2000000000000a0 ll
; 		.lpm_key = { IPCACHE_PREFIX_LEN(prefix), {} },
     354:	*(u64 *)(r10 - 0x48) = r1
; 		.ip6 = *addr,
     355:	w1 = *(u8 *)(r0 + 0x8)
     356:	w3 = *(u8 *)(r0 + 0x9)
     357:	r3 <<= 0x8
     358:	r3 |= r1
     359:	w1 = *(u8 *)(r0 + 0xa)
     360:	r1 <<= 0x10
     361:	w2 = *(u8 *)(r0 + 0xb)
     362:	r2 <<= 0x18
     363:	r2 |= r1
     364:	r2 |= r3
     365:	w3 = *(u8 *)(r0 + 0xd)
     366:	w3 <<= 0x8
     367:	w1 = *(u8 *)(r0 + 0xc)
     368:	w3 |= w1
     369:	w4 = *(u8 *)(r0 + 0xe)
     370:	w4 <<= 0x10
     371:	w1 = *(u8 *)(r0 + 0xf)
     372:	w1 <<= 0x18
     373:	w1 |= w4
     374:	w1 |= w3
     375:	r1 <<= 0x20
     376:	r1 |= r2
     377:	w2 = *(u8 *)(r0 + 0x10)
     378:	w4 = *(u8 *)(r0 + 0x11)
     379:	r4 <<= 0x8
     380:	r4 |= r2
     381:	w3 = *(u8 *)(r0 + 0x12)
     382:	r3 <<= 0x10
     383:	w2 = *(u8 *)(r0 + 0x13)
     384:	r2 <<= 0x18
     385:	r2 |= r3
     386:	w3 = *(u8 *)(r0 + 0x17)
     387:	w5 = *(u8 *)(r0 + 0x16)
     388:	r7 = r0
     389:	w0 = *(u8 *)(r7 + 0x14)
     390:	*(u64 *)(r10 - 0x98) = r6
     391:	*(u64 *)(r10 - 0xa8) = r7
     392:	w6 = *(u8 *)(r7 + 0x15)
     393:	w7 = 0x0
; 	key.cluster_id = (__u16)cluster_id;
     394:	*(u16 *)(r10 - 0x44) = w7
; 		.ip6 = *addr,
     395:	*(u64 *)(r10 - 0x40) = r1
     396:	r2 |= r4
     397:	w6 <<= 0x8
     398:	w6 |= w0
     399:	w5 <<= 0x10
     400:	w3 <<= 0x18
     401:	w3 |= w5
     402:	w3 |= w6
     403:	r6 = *(u64 *)(r10 - 0x98)
     404:	r3 <<= 0x20
     405:	r3 |= r2
     406:	*(u64 *)(r10 - 0x38) = r3
     407:	r2 = r10
     408:	r2 += -0x48
; 	return map_lookup_elem(map, &key);
     409:	r1 = 0x0 ll
     411:	call 0x1
; 	decrypted = ((ctx->mark & MARK_MAGIC_HOST_MASK) == MARK_MAGIC_DECRYPT);
     412:	w1 = *(u32 *)(r6 + 0x8)
     413:	w1 &= 0xf00
; 	if (decrypted) {
     414:	if w1 != 0xd00 goto +0x2 <LBB16_252>
; 		if (info)
     415:	if r0 == 0x0 goto +0xb <LBB16_257>
     416:	goto +0x8 <LBB16_256>

0000000000000d08 <LBB16_252>:
; 		if (info && (identity_is_remote_node(*identity) ||
     417:	if r0 == 0x0 goto +0x9 <LBB16_257>
     418:	w2 = *(u32 *)(r10 - 0x90)
     419:	w2 &= -0x1000000
; 	return identity == REMOTE_NODE_ID ||
     420:	if w2 == 0x2000000 goto +0x4 <LBB16_256>
     421:	w2 = *(u32 *)(r10 - 0x90)
     422:	if w2 == 0x7 goto +0x2 <LBB16_256>
     423:	w2 = *(u32 *)(r10 - 0x90)
     424:	if w2 != 0x6 goto +0x2 <LBB16_257>

0000000000000d48 <LBB16_256>:
     425:	w2 = *(u32 *)(r0 + 0x0)
     426:	*(u32 *)(r10 - 0x90) = w2

0000000000000d58 <LBB16_257>:
; 	if (!decrypted) {
     427:	if w1 == 0xd00 goto +0x20 <LBB16_270>
     428:	r1 = *(u64 *)(r10 - 0xa8)
; 		if (ip6->nexthdr != IPPROTO_ESP) {
     429:	w2 = *(u8 *)(r1 + 0x6)
     430:	*(u32 *)(r10 - 0xb0) = w2
     431:	if w2 == 0x32 goto +0x20 <LBB16_262>
; 	return ctx->len;
     432:	w7 = *(u32 *)(r6 + 0x0)
     433:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
     434:	*(u64 *)(r10 - 0x40) = r1
     435:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
     436:	*(u64 *)(r10 - 0x70) = r1
     437:	w1 = 0x3
; 	key.reason = reason;
     438:	*(u8 *)(r10 - 0x70) = w1
; 	key.file   = file;
     439:	*(u8 *)(r10 - 0x6c) = w1
     440:	w1 = 0x77
; 	key.line   = line;
     441:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
     442:	w1 = *(u8 *)(r10 - 0x6f)
     443:	w1 &= 0xfc
     444:	w1 |= 0x1
     445:	*(u8 *)(r10 - 0x6f) = w1
     446:	r2 = r10
     447:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
     448:	r1 = 0x0 ll
     450:	call 0x1
; 	if (entry) {
     451:	if r0 == 0x0 goto +0x127 <LBB16_261>
; 		entry->count += 1;
     452:	r1 = *(u64 *)(r0 + 0x0)
     453:	r1 += 0x1
     454:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
     455:	r1 = *(u64 *)(r0 + 0x8)
     456:	r1 += r7
     457:	*(u64 *)(r0 + 0x8) = r1
     458:	w9 = w8
     459:	goto +0x139 <LBB16_269>

0000000000000e60 <LBB16_270>:
     460:	w1 = 0x0
; 	ctx->mark = 0;
     461:	*(u32 *)(r6 + 0x8) = w1
     462:	r8 = *(u64 *)(r10 - 0xa8)
     463:	goto +0x139 <LBB16_271>

0000000000000e80 <LBB16_262>:
     464:	r1 += 0x8
     465:	r2 = 0x0
; 	struct node_key node_ip = {};
     466:	*(u64 *)(r10 - 0x48) = r2
     467:	*(u64 *)(r10 - 0x40) = r2
     468:	w2 = 0x2
; 	node_ip.family = ENDPOINT_KEY_IPV6;
     469:	*(u8 *)(r10 - 0x45) = w2
; 	struct node_key node_ip = {};
     470:	*(u32 *)(r10 - 0x38) = w7
; 	node_ip.ip6 = *ip6;
     471:	w3 = *(u8 *)(r1 + 0x5)
     472:	w3 <<= 0x8
     473:	w2 = *(u8 *)(r1 + 0x4)
     474:	w3 |= w2
     475:	w4 = *(u8 *)(r1 + 0x6)
     476:	w4 <<= 0x10
     477:	w2 = *(u8 *)(r1 + 0x7)
     478:	w2 <<= 0x18
     479:	w2 |= w4
     480:	w5 = *(u8 *)(r1 + 0x9)
     481:	w5 <<= 0x8
     482:	w4 = *(u8 *)(r1 + 0x8)
     483:	w5 |= w4
     484:	w0 = *(u8 *)(r1 + 0xa)
     485:	w0 <<= 0x10
     486:	w4 = *(u8 *)(r1 + 0xb)
     487:	w4 <<= 0x18
     488:	w4 |= w0
     489:	w4 |= w5
     490:	w2 |= w3
     491:	w3 = *(u8 *)(r1 + 0x1)
     492:	w3 <<= 0x8
     493:	w5 = *(u8 *)(r1 + 0x0)
     494:	w3 |= w5
     495:	w5 = *(u8 *)(r1 + 0x2)
     496:	w5 <<= 0x10
     497:	w0 = *(u8 *)(r1 + 0x3)
     498:	w0 <<= 0x18
     499:	w0 |= w5
     500:	w0 |= w3
     501:	*(u32 *)(r10 - 0x44) = w0
     502:	*(u32 *)(r10 - 0x40) = w2
     503:	*(u32 *)(r10 - 0x3c) = w4
     504:	w2 = *(u8 *)(r1 + 0xd)
     505:	w2 <<= 0x8
     506:	w3 = *(u8 *)(r1 + 0xc)
     507:	w2 |= w3
     508:	w3 = *(u8 *)(r1 + 0xe)
     509:	w3 <<= 0x10
     510:	w1 = *(u8 *)(r1 + 0xf)
     511:	w1 <<= 0x18
     512:	w1 |= w3
     513:	w1 |= w2
     514:	*(u32 *)(r10 - 0x38) = w1
     515:	r2 = r10
     516:	r2 += -0x48
; 	node_value = map_lookup_elem(&NODE_MAP_V2, &node_ip);
     517:	r1 = 0x0 ll
     519:	call 0x1
; 	if (!node_value)
     520:	if r0 == 0x0 goto +0x1 <LBB16_264>
; 	if (!node_value->id)
     521:	w7 = *(u16 *)(r0 + 0x0)

0000000000001050 <LBB16_264>:
     522:	w9 = -0xc5
; 		if (!node_id)
     523:	w1 = w7
     524:	w1 &= 0xffff
     525:	if w1 == 0x0 goto +0xf7 <LBB16_269>
; 	ctx->mark = MARK_MAGIC_DECRYPT | node_id << 16;
     526:	w7 <<= 0x10
     527:	w7 |= 0xd00
     528:	*(u32 *)(r6 + 0x8) = w7
     529:	r7 = r6
     530:	w6 = 0x0
; 		ctx_change_type(ctx, PACKET_HOST);
     531:	r1 = r7
     532:	w2 = 0x0
     533:	call 0x20
; 	return ctx->len;
     534:	w7 = *(u32 *)(r7 + 0x0)
     535:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
     536:	*(u64 *)(r10 - 0x40) = r1
     537:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
     538:	*(u64 *)(r10 - 0x70) = r1
; 	key.reason = reason;
     539:	*(u8 *)(r10 - 0x70) = w6
     540:	w1 = 0x6f
; 	key.file   = file;
     541:	*(u8 *)(r10 - 0x6c) = w1
     542:	w1 = 0x151
; 	key.line   = line;
     543:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
     544:	w1 = *(u8 *)(r10 - 0x6f)
     545:	w1 &= 0xfc
     546:	w1 |= 0x2
     547:	*(u8 *)(r10 - 0x6f) = w1
     548:	r2 = r10
     549:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
     550:	r1 = 0x0 ll
     552:	call 0x1
; 	if (entry) {
     553:	if r0 == 0x0 goto +0xce <LBB16_267>
; 		entry->count += 1;
     554:	r1 = *(u64 *)(r0 + 0x0)
     555:	r1 += 0x1
     556:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
     557:	r1 = *(u64 *)(r0 + 0x8)
     558:	r1 += r7
     559:	*(u64 *)(r0 + 0x8) = r1
     560:	goto +0xd2 <LBB16_268>

0000000000001188 <LBB16_61>:
     561:	*(u64 *)(r10 - 0xb8) = r7
; 	state->rev_nat_index = svc->rev_nat_index;
     562:	w1 = *(u16 *)(r7 + 0x6)
; 	__u8 flags = tuple->flags;
     563:	*(u32 *)(r10 - 0xc0) = w1
     564:	w1 = *(u8 *)(r10 - 0x4b)
     565:	*(u32 *)(r10 - 0xc8) = w1
     566:	w1 = 0x4
; 	tuple->flags = ct_lookup_select_tuple_type(dir, scope);
     567:	*(u8 *)(r10 - 0x4b) = w1
     568:	r3 = 0x0 ll
; 	if (tuple->nexthdr == IPPROTO_TCP)
     570:	w2 = *(u8 *)(r10 - 0x4c)
     571:	if w2 == 0x6 goto +0x2 <LBB16_63>
     572:	r3 = 0x0 ll

00000000000011f0 <LBB16_63>:
; 	case  8: jmp_8:  __it_mob(d, s, 64);
     574:	r1 = *(u64 *)(r10 - 0x60)
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
     575:	*(u64 *)(r10 - 0xe0) = r1
     576:	r1 = *(u64 *)(r10 - 0x58)
     577:	*(u64 *)(r10 - 0xe8) = r1
     578:	w8 = 0x0
; 	union tcp_flags tcp_flags = { .value = 0 };
     579:	*(u32 *)(r10 - 0x48) = w8
     580:	w9 = 0x0
     581:	*(u32 *)(r10 - 0xf0) = w2
; 	if (is_tcp) {
     582:	*(u64 *)(r10 - 0xd0) = r3
     583:	if w2 != 0x6 goto +0x13 <LBB16_68>
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
     584:	w2 = *(u32 *)(r10 - 0xb0)
     585:	w2 += 0xc
     586:	r3 = r10
     587:	r3 += -0x48
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
     588:	r1 = r6
     589:	w4 = 0x2
     590:	call 0x1a
     591:	w1 = -0x87
     592:	w7 = 0x0
     593:	w5 = 0x0
; 		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
     594:	if w0 s< 0x0 goto +0x1e8 <LBB16_99>
; 		action = ct_tcp_select_action(tcp_flags);
     595:	w9 = *(u32 *)(r10 - 0x48)
; 	if (unlikely(flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
     596:	w1 = w9
     597:	w1 &= 0x500
     598:	w9 >>= 0x9
     599:	w9 &= 0x1
     600:	if w1 == 0x0 goto +0x1 <LBB16_67>
     601:	w9 = 0x2

00000000000012d0 <LBB16_67>:
     602:	r3 = *(u64 *)(r10 - 0xd0)

00000000000012d8 <LBB16_68>:
; 		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_entry_types,
     603:	w1 = *(u32 *)(r10 - 0x48)
; 	entry = map_lookup_elem(map, tuple);
     604:	*(u32 *)(r10 - 0xd8) = w1
     605:	r2 = r10
     606:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
     607:	r1 = r3
     608:	call 0x1
     609:	r7 = r0
     610:	w1 = 0x1
     611:	*(u32 *)(r10 - 0xa0) = w1
     612:	w5 = 0x0
     613:	w1 = 0x0
; 	if (entry) {
     614:	if r7 == 0x0 goto +0x1ca <LBB16_95>
; 	    entry->rev_nat_index == state->rev_nat_index)
     615:	w1 = *(u32 *)(r10 - 0xc0)
     616:	r2 = r1
     617:	w3 = *(u16 *)(r7 + 0x26)
     618:	w5 = 0x0
     619:	w1 = 0x0
; 	if ((ct_entry_types & CT_ENTRY_SVC) &&
     620:	if w3 != w2 goto +0x1c4 <LBB16_95>
     621:	w1 = *(u32 *)(r10 - 0xd8)
     622:	w1 &= 0x200
     623:	*(u32 *)(r10 - 0xf8) = w1
; 		if (dir == CT_SERVICE && syn &&
     624:	if w1 == 0x0 goto +0xa <LBB16_73>
; 	return entry->tx_closing || entry->rx_closing;
     625:	w1 = *(u16 *)(r7 + 0x24)
     626:	w1 &= 0x3
; 		    ct_entry_closing(entry) &&
     627:	if w1 == 0x0 goto +0x7 <LBB16_73>
; 	return READ_ONCE(entry->last_tx_report) + wait_time <= bpf_mono_now();
     628:	w6 = *(u32 *)(r7 + 0x30)
     629:	w6 += 0x1e
     630:	call 0x5
     631:	r0 /= 0x3b9aca00
     632:	w5 = 0x0
     633:	w1 = 0x0
; 		if (dir == CT_SERVICE && syn &&
     634:	if r0 >= r6 goto +0x1b6 <LBB16_95>

00000000000013d8 <LBB16_73>:
; 	return !entry->rx_closing || !entry->tx_closing;
     635:	w1 = *(u16 *)(r7 + 0x24)
     636:	w2 = w1
     637:	w2 &= 0x3
     638:	r6 = *(u64 *)(r10 - 0x98)
; 		if (ct_entry_alive(entry))
     639:	if w2 == 0x3 goto +0x1e <LBB16_80>
     640:	w8 = 0x3c
; 	if (tcp) {
     641:	w2 = *(u32 *)(r10 - 0xf0)
     642:	if w2 != 0x6 goto +0x9 <LBB16_77>
; 		entry->seen_non_syn |= !syn;
     643:	w2 = *(u32 *)(r10 - 0xd8)
     644:	w2 ^= -0x1
     645:	w2 >>= 0x5
     646:	w2 &= 0x10
     647:	w1 |= w2
     648:	*(u16 *)(r7 + 0x24) = w1
; 		if (entry->seen_non_syn) {
     649:	w1 &= 0x10
     650:	if w1 == 0x0 goto +0x1 <LBB16_77>
     651:	w8 = 0x5460

0000000000001460 <LBB16_77>:
; 	__u32 now = (__u32)bpf_mono_now();
     652:	call 0x5
     653:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
     654:	w8 += w0
     655:	*(u32 *)(r7 + 0x20) = w8
; 	barrier();
     656:	w3 = *(u32 *)(r10 - 0xd8)
     657:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
     658:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     659:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
     660:	w1 = w2
     661:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
     662:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     663:	w3 += 0x5
     664:	if w3 < w0 goto +0x3 <LBB16_79>
     665:	w3 = w1
     666:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     667:	if w2 == w3 goto +0x2 <LBB16_80>

00000000000014e0 <LBB16_79>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
     668:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
     669:	*(u32 *)(r7 + 0x30) = w0

00000000000014f0 <LBB16_80>:
; 		if (dir == CT_SERVICE && entry->rev_nat_index == 0)
     670:	w1 = *(u16 *)(r7 + 0x26)
     671:	if w1 != 0x0 goto +0x2 <LBB16_82>
; 			entry->rev_nat_index = ct_state->rev_nat_index;
     672:	w1 = *(u32 *)(r10 - 0xc0)
     673:	*(u16 *)(r7 + 0x26) = w1

0000000000001510 <LBB16_82>:
     674:	r1 = 0x1
; 		__sync_fetch_and_add(&entry->packets, 1);
     675:	lock *(u64 *)(r7 + 0x10) += r1
; 	return ctx->len;
     676:	w1 = *(u32 *)(r6 + 0x0)
; 		__sync_fetch_and_add(&entry->bytes, ctx_full_len(ctx));
     677:	lock *(u64 *)(r7 + 0x18) += r1
; 		switch (action) {
     678:	if w9 == 0x2 goto +0x16a <LBB16_91>
     679:	w8 = 0x0
; 		switch (action) {
     680:	if w9 != 0x1 goto +0x17f <LBB16_94>
; 	return entry->tx_closing || entry->rx_closing;
     681:	w1 = *(u16 *)(r7 + 0x24)
     682:	w2 = w1
     683:	w2 &= 0x3
; 			if (unlikely(ct_entry_closing(entry))) {
     684:	if w2 == 0x0 goto +0x17b <LBB16_94>
; 	entry->tx_flags_seen = 0;
     685:	*(u16 *)(r7 + 0x2a) = w8
; 				entry->seen_non_syn = false;
     686:	w1 &= 0xffec
     687:	*(u16 *)(r7 + 0x24) = w1
     688:	w9 = 0x3c
; 	if (tcp) {
     689:	w2 = *(u32 *)(r10 - 0xf0)
     690:	if w2 != 0x6 goto +0x8 <LBB16_88>
; 		entry->seen_non_syn |= !syn;
     691:	w2 = *(u32 *)(r10 - 0xd8)
     692:	w2 ^= -0x1
     693:	w2 >>= 0x5
     694:	w2 &= 0x10
     695:	w1 |= w2
     696:	*(u16 *)(r7 + 0x24) = w1
     697:	if w2 == 0x0 goto +0x1 <LBB16_88>
     698:	w9 = 0x5460

00000000000015d8 <LBB16_88>:
; 	__u32 now = (__u32)bpf_mono_now();
     699:	call 0x5
     700:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
     701:	w9 += w0
     702:	*(u32 *)(r7 + 0x20) = w9
; 	barrier();
     703:	w3 = *(u32 *)(r10 - 0xd8)
     704:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
     705:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     706:	w1 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
     707:	w2 = w1
     708:	w2 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
     709:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     710:	w3 += 0x5
     711:	if w3 < w0 goto +0x6 <LBB16_90>
     712:	w3 = w2
     713:	w3 &= 0xff
     714:	r4 = r1
     715:	w5 = 0x0
     716:	w1 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
     717:	if w4 == w3 goto +0x163 <LBB16_95>

0000000000001670 <LBB16_90>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
     718:	*(u8 *)(r7 + 0x2a) = w2
; 			WRITE_ONCE(entry->last_tx_report, now);
     719:	*(u32 *)(r7 + 0x30) = w0
; 	barrier();
     720:	w5 = 0x0
     721:	w1 = 0x0
     722:	goto +0x15e <LBB16_95>

0000000000001698 <LBB16_56>:
     723:	r3 = r10
     724:	r3 += -0x10
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     725:	r1 = r6
     726:	w2 = 0x6
     727:	w4 = 0x6
     728:	w5 = 0x0
     729:	call 0x9
     730:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     731:	if w0 s< 0x0 goto +0x9 <LBB16_59>
     732:	r3 = r10
     733:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     734:	r1 = r6
     735:	w2 = 0x0
     736:	w4 = 0x6
     737:	w5 = 0x0
     738:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     739:	if w0 s< 0x0 goto +0x1 <LBB16_59>
     740:	w9 = 0x0

0000000000001728 <LBB16_59>:
; 	if (IS_ERR(ret))
     741:	if w9 s< 0x0 goto -0x194 <LBB16_245>
; 	return redirect(ifindex, flags);
     742:	w1 = 0x1
     743:	w2 = 0x0
     744:	call 0x17
     745:	w9 = w0
     746:	goto -0x199 <LBB16_245>

0000000000001758 <LBB16_261>:
; 		new_entry.bytes = bytes;
     747:	*(u64 *)(r10 - 0x40) = r7
     748:	r1 = 0x1
; 		new_entry.count = 1;
     749:	*(u64 *)(r10 - 0x48) = r1
     750:	r2 = r10
; 		new_entry.bytes = bytes;
     751:	r2 += -0x70
     752:	r3 = r10
     753:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
     754:	r1 = 0x0 ll
     756:	w4 = 0x0
     757:	call 0x2
     758:	w9 = w8
     759:	goto +0xd <LBB16_269>

00000000000017c0 <LBB16_267>:
; 		new_entry.bytes = bytes;
     760:	*(u64 *)(r10 - 0x40) = r7
     761:	r1 = 0x1
; 		new_entry.count = 1;
     762:	*(u64 *)(r10 - 0x48) = r1
     763:	r2 = r10
; 		new_entry.bytes = bytes;
     764:	r2 += -0x70
     765:	r3 = r10
     766:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
     767:	r1 = 0x0 ll
     769:	w4 = 0x0
     770:	call 0x2

0000000000001818 <LBB16_268>:
     771:	w9 = 0x0
     772:	r6 = *(u64 *)(r10 - 0x98)

0000000000001828 <LBB16_269>:
     773:	r8 = *(u64 *)(r10 - 0xa8)
     774:	w7 = *(u32 *)(r10 - 0xa0)
     775:	w1 = *(u32 *)(r10 - 0xb0)
     776:	if w1 == 0x32 goto +0xd0 <LBB16_296>

0000000000001848 <LBB16_271>:
     777:	w1 = 0x0
; 	key.ip6 = *ip6;
     778:	*(u32 *)(r10 - 0x38) = w1
     779:	w1 = *(u8 *)(r8 + 0x18)
     780:	w3 = *(u8 *)(r8 + 0x19)
     781:	r3 <<= 0x8
     782:	r3 |= r1
     783:	w1 = *(u8 *)(r8 + 0x1a)
     784:	r1 <<= 0x10
     785:	w2 = *(u8 *)(r8 + 0x1b)
     786:	r2 <<= 0x18
     787:	r2 |= r1
     788:	r2 |= r3
     789:	w3 = *(u8 *)(r8 + 0x1d)
     790:	w3 <<= 0x8
     791:	w1 = *(u8 *)(r8 + 0x1c)
     792:	w3 |= w1
     793:	w4 = *(u8 *)(r8 + 0x1e)
     794:	w4 <<= 0x10
     795:	w1 = *(u8 *)(r8 + 0x1f)
     796:	w1 <<= 0x18
     797:	w1 |= w4
     798:	w1 |= w3
     799:	r1 <<= 0x20
     800:	r1 |= r2
     801:	w2 = *(u8 *)(r8 + 0x20)
     802:	w4 = *(u8 *)(r8 + 0x21)
     803:	r4 <<= 0x8
     804:	r4 |= r2
     805:	w3 = *(u8 *)(r8 + 0x22)
     806:	r3 <<= 0x10
     807:	w2 = *(u8 *)(r8 + 0x23)
     808:	r2 <<= 0x18
     809:	r2 |= r3
     810:	w3 = *(u8 *)(r8 + 0x27)
     811:	w5 = *(u8 *)(r8 + 0x26)
     812:	w0 = *(u8 *)(r8 + 0x24)
     813:	w6 = *(u8 *)(r8 + 0x25)
     814:	w7 = 0x2
; 	key.family = ENDPOINT_KEY_IPV6;
     815:	*(u8 *)(r10 - 0x38) = w7
; 	key.ip6 = *ip6;
     816:	*(u64 *)(r10 - 0x48) = r1
     817:	r2 |= r4
     818:	w6 <<= 0x8
     819:	w6 |= w0
     820:	w5 <<= 0x10
     821:	w3 <<= 0x18
     822:	w3 |= w5
     823:	w3 |= w6
     824:	r3 <<= 0x20
     825:	r3 |= r2
     826:	*(u64 *)(r10 - 0x40) = r3
     827:	r2 = r10
     828:	r2 += -0x48
; 	return map_lookup_elem(&ENDPOINTS_MAP, &key);
     829:	r1 = 0x0 ll
     831:	call 0x1
     832:	r7 = r0
; 	if (ep && !(ep->flags & ENDPOINT_MASK_HOST_DELIVERY))
     833:	if r7 == 0x0 goto +0x2c <LBB16_285>
     834:	w1 = *(u32 *)(r7 + 0x8)
     835:	w1 &= 0x3
     836:	if w1 != 0x0 goto +0x29 <LBB16_285>
; 	mac_t router_mac = ep->node_mac;
     837:	r1 = *(u64 *)(r7 + 0x18)
     838:	*(u64 *)(r10 - 0x48) = r1
; 	mac_t lxc_mac = ep->mac;
     839:	r1 = *(u64 *)(r7 + 0x10)
     840:	*(u64 *)(r10 - 0x70) = r1
     841:	r3 = r10
     842:	r3 += -0x88
     843:	r6 = *(u64 *)(r10 - 0x98)
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     844:	r1 = r6
     845:	w2 = 0x7
     846:	w4 = 0x1
     847:	call 0x1a
     848:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     849:	if w0 s< 0x0 goto +0xf <LBB16_276>
     850:	w9 = -0xc4
; 	if (hl <= 1)
     851:	w1 = *(u8 *)(r10 - 0x88)
     852:	if w1 < 0x2 goto +0xc <LBB16_276>
; 	hl--;
     853:	w1 += -0x1
     854:	*(u8 *)(r10 - 0x88) = w1
     855:	r3 = r10
; 	hl--;
     856:	r3 += -0x88
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     857:	r1 = r6
     858:	w2 = 0x7
     859:	w4 = 0x1
     860:	w5 = 0x1
     861:	call 0x9
     862:	w9 = w0
     863:	w9 s>>= 0x1f
     864:	w9 &= -0x8d

0000000000001b08 <LBB16_276>:
; 	if (IS_ERR(ret)) {
     865:	if w9 s> -0x1 goto +0x55 <LBB16_279>
; 		if (ret == DROP_TTL_EXCEEDED)
     866:	if w9 != -0xc4 goto +0x66 <LBB16_282>
     867:	w1 = 0x1
; 	ctx->cb[off] = data;
     868:	*(u32 *)(r6 + 0x34) = w1
     869:	w1 = 0x0
     870:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     871:	r1 = r6
     872:	r2 = 0x0 ll
     874:	r3 = 0x5
     875:	call 0xc
     876:	w9 = -0x8c
     877:	goto +0x5b <LBB16_282>

0000000000001b70 <LBB16_285>:
     878:	r1 = 0x568803a772ce ll
; 		union macaddr host_mac = HOST_IFINDEX_MAC;
     880:	*(u64 *)(r10 - 0x48) = r1
; 		union macaddr router_mac = THIS_INTERFACE_MAC;
     881:	r1 = 0x0 ll
     883:	w1 = *(u32 *)(r1 + 0x0)
     884:	*(u32 *)(r10 - 0x70) = w1
     885:	r1 = 0x0 ll
     887:	w1 = *(u32 *)(r1 + 0x0)
     888:	*(u16 *)(r10 - 0x6c) = w1
     889:	r3 = r10
; 		union macaddr host_mac = HOST_IFINDEX_MAC;
     890:	r3 += -0x88
     891:	r6 = *(u64 *)(r10 - 0x98)
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     892:	r1 = r6
     893:	w2 = 0x7
     894:	w4 = 0x1
     895:	call 0x1a
     896:	w9 = -0x86
; 	if (ctx_load_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     897:	if w0 s< 0x0 goto +0xf <LBB16_288>
     898:	w9 = -0xc4
; 	if (hl <= 1)
     899:	w1 = *(u8 *)(r10 - 0x88)
     900:	if w1 < 0x2 goto +0xc <LBB16_288>
; 	hl--;
     901:	w1 += -0x1
     902:	*(u8 *)(r10 - 0x88) = w1
     903:	r3 = r10
; 	hl--;
     904:	r3 += -0x88
; 	if (ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, hop_limit),
     905:	r1 = r6
     906:	w2 = 0x7
     907:	w4 = 0x1
     908:	w5 = 0x1
     909:	call 0x9
     910:	w9 = w0
     911:	w9 s>>= 0x1f
     912:	w9 &= -0x8d

0000000000001c88 <LBB16_288>:
     913:	w7 = *(u32 *)(r10 - 0xa0)
; 	if (IS_ERR(ret)) {
     914:	if w9 s> -0x1 goto +0xc <LBB16_291>
; 		if (ret == DROP_TTL_EXCEEDED)
     915:	if w9 != -0xc4 goto +0x1d <LBB16_294>
     916:	w1 = 0x1
; 	ctx->cb[off] = data;
     917:	*(u32 *)(r6 + 0x34) = w1
     918:	w1 = 0x0
     919:	*(u32 *)(r6 + 0x30) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
     920:	r1 = r6
     921:	r2 = 0x0 ll
     923:	r3 = 0x5
     924:	call 0xc
     925:	w9 = -0x8c
     926:	goto +0x12 <LBB16_294>

0000000000001cf8 <LBB16_291>:
     927:	r3 = r10
     928:	r3 += -0x70
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     929:	r1 = r6
     930:	w2 = 0x6
     931:	w4 = 0x6
     932:	w5 = 0x0
     933:	call 0x9
     934:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     935:	if w0 s< 0x0 goto +0x9 <LBB16_294>
     936:	r3 = r10
     937:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     938:	r1 = r6
     939:	w2 = 0x0
     940:	w4 = 0x6
     941:	w5 = 0x0
     942:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     943:	if w0 s< 0x0 goto +0x1 <LBB16_294>
     944:	w9 = 0x0

0000000000001d88 <LBB16_294>:
; 		if (ret != CTX_ACT_OK)
     945:	if w9 != 0x0 goto +0x27 <LBB16_296>
; 	return redirect(ifindex, flags);
     946:	w1 = 0x1
     947:	w2 = 0x0
     948:	call 0x17
     949:	w9 = w0
     950:	goto +0x22 <LBB16_296>

0000000000001db8 <LBB16_279>:
     951:	r3 = r10
     952:	r3 += -0x48
; 	return ctx_store_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN, 0);
     953:	r1 = r6
     954:	w2 = 0x6
     955:	w4 = 0x6
     956:	w5 = 0x0
     957:	call 0x9
     958:	w9 = -0x8d
; 	if (smac && eth_store_saddr(ctx, smac, 0) < 0)
     959:	if w0 s< 0x0 goto +0x9 <LBB16_282>
     960:	r3 = r10
     961:	r3 += -0x70
; 	return ctx_store_bytes(ctx, off, mac, ETH_ALEN, 0);
     962:	r1 = r6
     963:	w2 = 0x0
     964:	w4 = 0x6
     965:	w5 = 0x0
     966:	call 0x9
; 	if (dmac && eth_store_daddr(ctx, dmac, 0) < 0)
     967:	if w0 s< 0x0 goto +0x1 <LBB16_282>
     968:	w9 = 0x0

0000000000001e48 <LBB16_282>:
; 	if (ret != CTX_ACT_OK)
     969:	if w9 != 0x0 goto +0xe <LBB16_284>
     970:	w1 = 0x1
; 	ctx->cb[off] = data;
     971:	*(u32 *)(r6 + 0x40) = w1
     972:	*(u32 *)(r6 + 0x34) = w1
     973:	w1 = *(u32 *)(r10 - 0x90)
     974:	*(u32 *)(r6 + 0x30) = w1
     975:	w1 = 0x0
; 	ctx->cb[off] = data;
     976:	*(u32 *)(r6 + 0x3c) = w1
     977:	*(u32 *)(r6 + 0x38) = w1
; 	return tail_call_policy(ctx, ep->lxc_id);
     978:	w3 = *(u16 *)(r7 + 0x6)
; 	tail_call(ctx, map, slot);
     979:	r1 = r6
     980:	r2 = 0x0 ll
     982:	call 0xc
     983:	w9 = -0xcb

0000000000001ec0 <LBB16_284>:
     984:	w7 = *(u32 *)(r10 - 0xa0)

0000000000001ec8 <LBB16_296>:
; 	if (IS_ERR(ret))
     985:	if w9 s< 0x0 goto +0x1 <LBB16_298>
     986:	if w9 != 0x2 goto +0x375 <LBB16_302>

0000000000001ed8 <LBB16_298>:
     987:	w1 = 0xb80302
; 	ctx->cb[off] = data;
     988:	*(u32 *)(r6 + 0x40) = w1
     989:	w1 = 0x0
     990:	*(u32 *)(r6 + 0x3c) = w1
     991:	*(u32 *)(r6 + 0x34) = w1
     992:	w1 = *(u32 *)(r10 - 0x90)
     993:	*(u32 *)(r6 + 0x30) = w1
; 		return send_drop_notify_error_ext(ctx, src_sec_identity, ret, ext_err,
     994:	w1 = w9
     995:	w1 s>>= 0x1f
     996:	w9 ^= w1
     997:	w9 -= w1
     998:	w7 &= 0xff
     999:	w7 <<= 0x8
    1000:	w1 = w9
    1001:	w1 &= 0xff
    1002:	w1 |= w7
; 	ctx->cb[off] = data;
    1003:	*(u32 *)(r6 + 0x38) = w1
    1004:	r7 = r6
; 	return ctx->len;
    1005:	w6 = *(u32 *)(r6 + 0x0)
    1006:	r1 = 0x0
; 	struct metrics_value *entry, new_entry = {};
    1007:	*(u64 *)(r10 - 0x40) = r1
    1008:	*(u64 *)(r10 - 0x48) = r1
; 	struct metrics_key key = {};
    1009:	*(u64 *)(r10 - 0x70) = r1
; 	key.reason = reason;
    1010:	*(u8 *)(r10 - 0x70) = w9
    1011:	w1 = 0x3
; 	key.file   = file;
    1012:	*(u8 *)(r10 - 0x6c) = w1
    1013:	w1 = 0xb8
; 	key.line   = line;
    1014:	*(u16 *)(r10 - 0x6e) = w1
; 	key.dir    = direction;
    1015:	w1 = *(u8 *)(r10 - 0x6f)
    1016:	w1 &= 0xfc
    1017:	w1 |= 0x1
    1018:	*(u8 *)(r10 - 0x6f) = w1
    1019:	r2 = r10
    1020:	r2 += -0x70
; 	entry = map_lookup_elem(&METRICS_MAP, &key);
    1021:	r1 = 0x0 ll
    1023:	call 0x1
; 	if (entry) {
    1024:	if r0 == 0x0 goto +0x33e <LBB16_300>
; 		entry->count += 1;
    1025:	r1 = *(u64 *)(r0 + 0x0)
    1026:	r1 += 0x1
    1027:	*(u64 *)(r0 + 0x0) = r1
; 		entry->bytes += bytes;
    1028:	r1 = *(u64 *)(r0 + 0x8)
    1029:	r1 += r6
    1030:	*(u64 *)(r0 + 0x8) = r1
    1031:	goto +0x342 <LBB16_301>

0000000000002040 <LBB16_27>:
    1032:	r3 = r10
; 			if (ctx_load_bytes(ctx, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
    1033:	r3 += -0x48
    1034:	r1 = *(u64 *)(r10 - 0x98)
    1035:	w2 = w8
    1036:	w4 = 0x2
    1037:	call 0x1a
    1038:	if w0 s< 0x0 goto -0x383 <LBB16_31>
    1039:	w7 = -0x9c
    1040:	goto -0x385 <LBB16_31>

0000000000002088 <LBB16_91>:
; 				entry->rx_closing = 1;
    1041:	w1 = *(u16 *)(r7 + 0x24)
; 				entry->tx_closing = 1;
    1042:	w1 |= 0x3
    1043:	*(u16 *)(r7 + 0x24) = w1
; 	__u32 now = (__u32)bpf_mono_now();
    1044:	call 0x5
    1045:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    1046:	w1 = w0
    1047:	w1 += 0xa
    1048:	*(u32 *)(r7 + 0x20) = w1
    1049:	w8 = 0x100
    1050:	w3 = *(u32 *)(r10 - 0xd8)
    1051:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    1052:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1053:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    1054:	w1 = w2
    1055:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    1056:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1057:	w3 += 0x5
    1058:	if w3 < w0 goto +0x3 <LBB16_93>
    1059:	w3 = w1
    1060:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1061:	if w2 == w3 goto +0x2 <LBB16_94>

0000000000002130 <LBB16_93>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    1062:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    1063:	*(u32 *)(r7 + 0x30) = w0

0000000000002140 <LBB16_94>:
    1064:	w1 = *(u32 *)(r10 - 0xf8)
; 		state->syn = syn;
    1065:	w1 >>= 0x6
    1066:	w8 |= w1
    1067:	w1 = 0x1
    1068:	w2 = 0x0
; 	state->rev_nat_index = entry->rev_nat_index;
    1069:	*(u32 *)(r10 - 0xa0) = w2
    1070:	w2 = *(u16 *)(r7 + 0x26)
; 		state->backend_id = (__u32)entry->backend_id;
    1071:	*(u32 *)(r10 - 0xc0) = w2
    1072:	r5 = *(u64 *)(r7 + 0x8)

0000000000002188 <LBB16_95>:
    1073:	r6 = *(u64 *)(r10 - 0x98)
; 		if (ret != CT_NEW) {
    1074:	w2 = *(u32 *)(r10 - 0xa0)
    1075:	if w2 != 0x0 goto +0x5 <LBB16_98>
; 			if (unlikely(tuple->flags & TUPLE_F_RELATED))
    1076:	w2 = *(u8 *)(r10 - 0x4b)
    1077:	w2 &= 0x2
    1078:	w1 = 0x2
    1079:	if w2 == 0x0 goto +0x1 <LBB16_98>
    1080:	w1 = 0x3

00000000000021c8 <LBB16_98>:
; 	cilium_dbg(ctx, DBG_CT_VERDICT, ret,
    1081:	w1 &= 0xff
    1082:	w7 = w8

00000000000021d8 <LBB16_99>:
    1083:	w2 = 0x0
    1084:	*(u32 *)(r10 - 0xa0) = w2
    1085:	w9 = w1
; 	if (ret < 0)
    1086:	if w1 s< 0x0 goto +0x33d <LBB16_169>
; 	switch (ret) {
    1087:	if w1 == 0x2 goto +0x56 <LBB16_135>
    1088:	w9 = -0xa3
; 	switch (ret) {
    1089:	*(u32 *)(r10 - 0xa0) = w2
    1090:	if w1 != 0x0 goto +0x339 <LBB16_169>
    1091:	w9 = -0x9e
; 		if (unlikely(svc->count == 0))
    1092:	r1 = *(u64 *)(r10 - 0xb8)
    1093:	w1 = *(u16 *)(r1 + 0x4)
    1094:	*(u32 *)(r10 - 0xa0) = w2
    1095:	if w1 == 0x0 goto +0x334 <LBB16_169>
    1096:	w3 = 0x0
; 	return svc->flags & SVC_FLAG_AFFINITY;
    1097:	r1 = *(u64 *)(r10 - 0xb8)
    1098:	w1 = *(u8 *)(r1 + 0x8)
    1099:	w1 &= 0x10
; 		if (lb6_svc_is_affinity(svc)) {
    1100:	if w1 == 0x0 goto +0x14e <LBB16_113>
    1101:	r1 = 0x0
; 	struct lb6_affinity_key key = {
    1102:	*(u64 *)(r10 - 0x38) = r1
    1103:	*(u64 *)(r10 - 0x40) = r1
    1104:	*(u64 *)(r10 - 0x48) = r1
; 		.rev_nat_id	= svc->rev_nat_index,
    1105:	r1 = *(u64 *)(r10 - 0xb8)
    1106:	w1 = *(u16 *)(r1 + 0x6)
; 	struct lb6_affinity_key key = {
    1107:	*(u16 *)(r10 - 0x38) = w1
; 	dst->d2 = src->d2;
    1108:	r1 = *(u64 *)(r10 - 0xe8)
    1109:	*(u64 *)(r10 - 0x40) = r1
; 	dst->d1 = src->d1;
    1110:	r1 = *(u64 *)(r10 - 0xe0)
    1111:	*(u64 *)(r10 - 0x48) = r1
; 	struct lb6_affinity_key key = {
    1112:	w1 = *(u8 *)(r10 - 0x36)
    1113:	w1 &= 0xfe
    1114:	*(u8 *)(r10 - 0x36) = w1
    1115:	r2 = r10
    1116:	r2 += -0x48
; 	val = map_lookup_elem(&LB6_AFFINITY_MAP, &key);
    1117:	r1 = 0x0 ll
    1119:	call 0x1
    1120:	r7 = r0
    1121:	w8 = 0x0
; 	if (val != NULL) {
    1122:	if r7 == 0x0 goto +0x12c <LBB16_110>
; 		__u32 now = (__u32)bpf_mono_now();
    1123:	call 0x5
; 			.backend_id	= val->backend_id,
    1124:	w1 = *(u8 *)(r7 + 0x9)
    1125:	w1 <<= 0x8
    1126:	w2 = *(u8 *)(r7 + 0x8)
    1127:	w1 |= w2
    1128:	w2 = *(u8 *)(r7 + 0xa)
    1129:	w2 <<= 0x10
    1130:	w3 = *(u8 *)(r7 + 0xb)
    1131:	w3 <<= 0x18
    1132:	w3 |= w2
    1133:	w3 |= w1
; 		struct lb_affinity_match match = {
    1134:	*(u32 *)(r10 - 0x10) = w3
    1135:	r5 = *(u64 *)(r10 - 0xb8)
; 			.rev_nat_id	= svc->rev_nat_index,
    1136:	w1 = *(u16 *)(r5 + 0x6)
; 		struct lb_affinity_match match = {
    1137:	*(u16 *)(r10 - 0xa) = w8
    1138:	*(u16 *)(r10 - 0xc) = w1
; 		if (READ_ONCE(val->last_used) +
    1139:	w1 = *(u8 *)(r7 + 0x0)
    1140:	w2 = *(u8 *)(r7 + 0x1)
    1141:	r2 <<= 0x8
    1142:	r2 |= r1
    1143:	w3 = *(u8 *)(r7 + 0x2)
    1144:	r3 <<= 0x10
    1145:	w1 = *(u8 *)(r7 + 0x3)
    1146:	r1 <<= 0x18
    1147:	r1 |= r3
    1148:	r1 |= r2
    1149:	w2 = *(u8 *)(r7 + 0x4)
    1150:	w3 = *(u8 *)(r7 + 0x5)
    1151:	w3 <<= 0x8
    1152:	w3 |= w2
    1153:	w4 = *(u8 *)(r7 + 0x6)
    1154:	w4 <<= 0x10
    1155:	w2 = *(u8 *)(r7 + 0x7)
    1156:	w2 <<= 0x18
    1157:	w2 |= w4
    1158:	w2 |= w3
    1159:	r2 <<= 0x20
    1160:	r2 |= r1
; 	return svc->affinity_timeout & AFFINITY_TIMEOUT_MASK;
    1161:	w1 = *(u32 *)(r5 + 0x0)
; 		    bpf_sec_to_mono(lb6_affinity_timeout(svc)) <= now) {
    1162:	r1 &= 0xffffff
; 		if (READ_ONCE(val->last_used) +
    1163:	r2 += r1
; 		__u32 now = (__u32)bpf_mono_now();
    1164:	r0 /= 0x3b9aca00
; 		    bpf_sec_to_mono(lb6_affinity_timeout(svc)) <= now) {
    1165:	r0 <<= 0x20
    1166:	r0 >>= 0x20
; 		if (READ_ONCE(val->last_used) +
    1167:	if r2 > r0 goto +0xde <LBB16_107>

0000000000002480 <LBB16_106>:
    1168:	r2 = r10
    1169:	r2 += -0x48
    1170:	r1 = 0x0 ll
    1172:	call 0x3
    1173:	goto +0xf9 <LBB16_110>

00000000000024b0 <LBB16_135>:
    1174:	*(u32 *)(r10 - 0x48) = w5
    1175:	r2 = r10
    1176:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1177:	r1 = 0x0 ll
    1179:	r8 = r5
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1180:	call 0x1
    1181:	r2 = r8
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1182:	r3 = r0
; 		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
    1183:	if r3 == 0x0 goto +0x6 <LBB16_138>
    1184:	w1 = 0x0
; 		if (unlikely(!backend || backend->flags != BE_STATE_ACTIVE)) {
    1185:	*(u32 *)(r10 - 0xa0) = w1
    1186:	w1 = *(u8 *)(r3 + 0x13)
    1187:	if w1 == 0x0 goto +0x223 <LBB16_149>
; 			if (backend && !state->syn)
    1188:	w7 &= 0x8
    1189:	if w7 == 0x0 goto +0x221 <LBB16_149>

0000000000002530 <LBB16_138>:
    1190:	w9 = -0x9e
; 			if (unlikely(svc->count == 0))
    1191:	r1 = *(u64 *)(r10 - 0xb8)
    1192:	w1 = *(u16 *)(r1 + 0x4)
    1193:	w2 = 0x0
    1194:	*(u32 *)(r10 - 0xa0) = w2
    1195:	if w1 == 0x0 goto +0x2d0 <LBB16_169>
    1196:	w7 = 0x0
; 	return svc->affinity_timeout >> LB_ALGORITHM_SHIFT;
    1197:	r1 = *(u64 *)(r10 - 0xb8)
    1198:	w1 = *(u32 *)(r1 + 0x0)
    1199:	w1 >>= 0x18
; 	switch (lb6_algorithm(svc)) {
    1200:	if w1 == 0x1 goto +0x2a1 <LBB16_144>
    1201:	if w1 != 0x2 goto +0x2ad <LBB16_146>
    1202:	w1 = 0x0
    1203:	w7 = 0x0
; 	__u32 zero = 0, index = svc->rev_nat_index;
    1204:	*(u32 *)(r10 - 0x48) = w1
    1205:	r1 = *(u64 *)(r10 - 0xb8)
    1206:	w1 = *(u16 *)(r1 + 0x6)
    1207:	*(u32 *)(r10 - 0x10) = w1
    1208:	r2 = r10
    1209:	r2 += -0x10
; 	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
    1210:	r1 = 0x0 ll
    1212:	call 0x1
; 	if (unlikely(!maglev_lut))
    1213:	if r0 == 0x0 goto +0x2a1 <LBB16_146>
    1214:	r2 = r10
    1215:	r2 += -0x48
; 	backend_ids = map_lookup_elem(maglev_lut, &zero);
    1216:	r1 = r0
    1217:	call 0x1
; 	if (unlikely(!backend_ids))
    1218:	if r0 == 0x0 goto +0x29c <LBB16_146>
; 	c = tuple->saddr.p3;
    1219:	w1 = *(u32 *)(r10 - 0x58)
; 	return (word << shift) | (word >> ((-shift) & 31));
    1220:	w2 = w1
    1221:	w2 >>= 0x1c
    1222:	w3 = w1
    1223:	w3 <<= 0x4
    1224:	w3 |= w2
; 	a = tuple->saddr.p1;
    1225:	w2 = *(u32 *)(r10 - 0x60)
; 	__jhash_mix(a, b, c);
    1226:	w2 -= w1
    1227:	w2 ^= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1228:	w3 = w2
    1229:	w3 >>= 0x1a
    1230:	w5 = w2
    1231:	w5 <<= 0x6
    1232:	w5 |= w3
; 	b = tuple->saddr.p2;
    1233:	w3 = *(u32 *)(r10 - 0x5c)
; 	__jhash_mix(a, b, c);
    1234:	w4 = w3
    1235:	w4 -= w2
    1236:	w4 ^= w5
    1237:	w1 += w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1238:	w3 = w4
    1239:	w3 >>= 0x18
    1240:	w6 = w4
    1241:	w6 <<= 0x8
    1242:	w6 |= w3
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1243:	w5 = *(u16 *)(r10 - 0x50)
    1244:	w5 <<= 0x10
    1245:	w3 = *(u16 *)(r10 - 0x4e)
    1246:	w5 |= w3
; 	__jhash_mix(a, b, c);
    1247:	w2 += w1
    1248:	w1 -= w4
    1249:	w1 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1250:	w3 = w1
    1251:	w3 >>= 0x10
    1252:	w6 = w1
    1253:	w6 <<= 0x10
    1254:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1255:	w4 += w2
    1256:	w2 -= w1
    1257:	w2 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1258:	w3 = w2
    1259:	w3 >>= 0xd
    1260:	w6 = w2
    1261:	w6 <<= 0x13
    1262:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1263:	w1 += w4
    1264:	w4 -= w2
    1265:	w4 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1266:	w3 = w4
    1267:	w3 >>= 0x1c
    1268:	w6 = w4
    1269:	w6 <<= 0x4
    1270:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1271:	w2 += w1
    1272:	w1 -= w4
    1273:	w1 ^= w6
; 	c += tuple->nexthdr;
    1274:	w3 = *(u8 *)(r10 - 0x4c)
    1275:	w1 += w3
; 	__jhash_mix(a, b, c);
    1276:	w3 = w2
    1277:	w3 += w5
; 	a += tuple->saddr.p4;
    1278:	w5 = *(u32 *)(r10 - 0x54)
    1279:	w2 += w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1280:	w5 = w1
    1281:	w5 >>= 0x1c
    1282:	w6 = w1
    1283:	w6 <<= 0x4
    1284:	w6 |= w5
; 	__jhash_mix(a, b, c);
    1285:	w2 -= w1
    1286:	w2 ^= w6
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1287:	w3 += w4
; 	return (word << shift) | (word >> ((-shift) & 31));
    1288:	w4 = w2
    1289:	w4 >>= 0x1a
    1290:	w5 = w2
    1291:	w5 <<= 0x6
    1292:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1293:	w1 += w3
    1294:	w3 -= w2
    1295:	w3 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1296:	w4 = w3
    1297:	w4 >>= 0x18
    1298:	w5 = w3
    1299:	w5 <<= 0x8
    1300:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1301:	w2 += w1
    1302:	w1 -= w3
    1303:	w1 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1304:	w4 = w1
    1305:	w4 >>= 0x10
    1306:	w5 = w1
    1307:	w5 <<= 0x10
    1308:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1309:	w3 += w2
    1310:	w2 -= w1
    1311:	w2 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1312:	w4 = w2
    1313:	w4 >>= 0xd
    1314:	w5 = w2
    1315:	w5 <<= 0x13
    1316:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1317:	w1 += w3
    1318:	w3 -= w2
    1319:	w3 ^= w5
    1320:	w2 += w1
    1321:	w4 = w3
    1322:	w4 += w2
; 	return (word << shift) | (word >> ((-shift) & 31));
    1323:	w5 = w4
    1324:	w5 >>= 0x12
    1325:	w6 = w4
    1326:	w6 <<= 0xe
    1327:	w6 |= w5
    1328:	w5 = w3
    1329:	w5 >>= 0x1c
; 	__jhash_mix(a, b, c);
    1330:	w1 -= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1331:	w3 <<= 0x4
    1332:	w3 |= w5
; 	__jhash_mix(a, b, c);
    1333:	w1 ^= w3
; 	__jhash_final(a, b, c);
    1334:	w1 ^= w4
    1335:	w1 -= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1336:	w3 = w1
    1337:	w3 >>= 0x15
    1338:	w5 = w1
    1339:	w5 <<= 0xb
    1340:	w5 |= w3
; 	a += HASH_INIT6_SEED;
    1341:	w2 += 0xeb9f
; 	__jhash_final(a, b, c);
    1342:	w3 = w1
    1343:	w3 ^= w2
    1344:	w3 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1345:	w2 = w3
    1346:	w2 >>= 0x7
    1347:	w5 = w3
    1348:	w5 <<= 0x19
    1349:	w5 |= w2
; 	__jhash_final(a, b, c);
    1350:	w2 = w3
    1351:	w2 ^= w4
    1352:	w2 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1353:	w4 = w2
    1354:	w4 >>= 0x10
    1355:	w5 = w2
    1356:	w5 <<= 0x10
    1357:	w5 |= w4
; 	__jhash_final(a, b, c);
    1358:	w4 = w2
    1359:	w4 ^= w1
    1360:	w4 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1361:	w1 = w4
    1362:	w1 >>= 0x1c
    1363:	w5 = w4
    1364:	w5 <<= 0x4
    1365:	w5 |= w1
; 	__jhash_final(a, b, c);
    1366:	w1 = w4
    1367:	w1 ^= w3
    1368:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1369:	w3 = w1
    1370:	w3 >>= 0x12
    1371:	w5 = w1
    1372:	w5 <<= 0xe
    1373:	w5 |= w3
; 	__jhash_final(a, b, c);
    1374:	w1 ^= w2
    1375:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1376:	w2 = w1
    1377:	w2 >>= 0x8
    1378:	w3 = w1
    1379:	w3 <<= 0x18
    1380:	w3 |= w2
; 	__jhash_final(a, b, c);
    1381:	w1 ^= w4
    1382:	w1 -= w3
; 	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
    1383:	w1 %= 0x7fed
    1384:	*(u32 *)(r10 - 0x10) = w1
; 	asm volatile("%[index] <<= 2\n\t"
    1385:	r1 <<= 0x2
    1386:	if r1 > 0x1ffb0 goto +0x1 <LBB16_138+0x630>
    1387:	r0 += r1
    1388:	w7 = *(u32 *)(r0 + 0x0)
    1389:	goto +0x1f1 <LBB16_146>

0000000000002b70 <LBB16_107>:
    1390:	*(u64 *)(r10 - 0xa0) = r0
    1391:	r2 = r10
; 		if (!map_lookup_elem(&LB_AFFINITY_MATCH_MAP, &match)) {
    1392:	r2 += -0x10
    1393:	r1 = 0x0 ll
    1395:	call 0x1
    1396:	if r0 != 0x0 goto +0x1 <LBB16_109>
    1397:	goto -0xe6 <LBB16_106>

0000000000002bb0 <LBB16_109>:
    1398:	r1 = 0x0
; 		WRITE_ONCE(val->last_used, now);
    1399:	*(u8 *)(r7 + 0x7) = w1
    1400:	*(u8 *)(r7 + 0x6) = w1
    1401:	*(u8 *)(r7 + 0x5) = w1
    1402:	*(u8 *)(r7 + 0x4) = w1
    1403:	r2 = *(u64 *)(r10 - 0xa0)
    1404:	*(u8 *)(r7 + 0x0) = w2
    1405:	r1 = r2
    1406:	r1 >>= 0x18
    1407:	*(u8 *)(r7 + 0x3) = w1
    1408:	r1 = r2
    1409:	r1 >>= 0x10
    1410:	*(u8 *)(r7 + 0x2) = w1
    1411:	r2 >>= 0x8
    1412:	*(u8 *)(r7 + 0x1) = w2
; 		return val->backend_id;
    1413:	w1 = *(u8 *)(r7 + 0x9)
    1414:	w1 <<= 0x8
    1415:	w2 = *(u8 *)(r7 + 0x8)
    1416:	w1 |= w2
    1417:	w2 = *(u8 *)(r7 + 0xa)
    1418:	w2 <<= 0x10
    1419:	w8 = *(u8 *)(r7 + 0xb)
    1420:	w8 <<= 0x18
    1421:	w8 |= w2
    1422:	w8 |= w1

0000000000002c78 <LBB16_110>:
    1423:	w3 = 0x0
; 			if (backend_id != 0) {
    1424:	if w8 == 0x0 goto +0xa <LBB16_113>
    1425:	*(u32 *)(r10 - 0x48) = w8
    1426:	r2 = r10
    1427:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1428:	r1 = 0x0 ll
    1430:	call 0x1
    1431:	w3 = w8
; 				if (backend == NULL)
    1432:	if r0 != 0x0 goto +0x2 <LBB16_113>
    1433:	r0 = 0x0
    1434:	w3 = 0x0

0000000000002cd8 <LBB16_113>:
; 		if (backend_id == 0) {
    1435:	if w3 != 0x0 goto +0xd9 <LBB16_123>
    1436:	w8 = 0x0
    1437:	r7 = *(u64 *)(r10 - 0xb8)
; 	return svc->affinity_timeout >> LB_ALGORITHM_SHIFT;
    1438:	w1 = *(u32 *)(r7 + 0x0)
    1439:	w1 >>= 0x18
; 	switch (lb6_algorithm(svc)) {
    1440:	if w1 == 0x1 goto +0xbd <LBB16_120>
    1441:	if w1 != 0x2 goto +0xc9 <LBB16_122>
    1442:	w1 = 0x0
    1443:	w8 = 0x0
; 	__u32 zero = 0, index = svc->rev_nat_index;
    1444:	*(u32 *)(r10 - 0x48) = w1
    1445:	w1 = *(u16 *)(r7 + 0x6)
    1446:	*(u32 *)(r10 - 0x10) = w1
    1447:	r2 = r10
    1448:	r2 += -0x10
; 	maglev_lut = map_lookup_elem(&LB6_MAGLEV_MAP_OUTER, &index);
    1449:	r1 = 0x0 ll
    1451:	call 0x1
; 	if (unlikely(!maglev_lut))
    1452:	if r0 == 0x0 goto +0xaf <LBB16_119>
    1453:	r2 = r10
    1454:	r2 += -0x48
; 	backend_ids = map_lookup_elem(maglev_lut, &zero);
    1455:	r1 = r0
    1456:	call 0x1
; 	if (unlikely(!backend_ids))
    1457:	if r0 == 0x0 goto +0xaa <LBB16_119>
; 	c = tuple->saddr.p3;
    1458:	w1 = *(u32 *)(r10 - 0x58)
; 	return (word << shift) | (word >> ((-shift) & 31));
    1459:	w2 = w1
    1460:	w2 >>= 0x1c
    1461:	w3 = w1
    1462:	w3 <<= 0x4
    1463:	w3 |= w2
; 	a = tuple->saddr.p1;
    1464:	w2 = *(u32 *)(r10 - 0x60)
; 	__jhash_mix(a, b, c);
    1465:	w2 -= w1
    1466:	w2 ^= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1467:	w3 = w2
    1468:	w3 >>= 0x1a
    1469:	w5 = w2
    1470:	w5 <<= 0x6
    1471:	w5 |= w3
; 	b = tuple->saddr.p2;
    1472:	w3 = *(u32 *)(r10 - 0x5c)
; 	__jhash_mix(a, b, c);
    1473:	w4 = w3
    1474:	w4 -= w2
    1475:	w4 ^= w5
    1476:	w1 += w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1477:	w3 = w4
    1478:	w3 >>= 0x18
    1479:	w6 = w4
    1480:	w6 <<= 0x8
    1481:	w6 |= w3
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1482:	w5 = *(u16 *)(r10 - 0x50)
    1483:	w5 <<= 0x10
    1484:	w3 = *(u16 *)(r10 - 0x4e)
    1485:	w5 |= w3
; 	__jhash_mix(a, b, c);
    1486:	w2 += w1
    1487:	w1 -= w4
    1488:	w1 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1489:	w3 = w1
    1490:	w3 >>= 0x10
    1491:	w6 = w1
    1492:	w6 <<= 0x10
    1493:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1494:	w4 += w2
    1495:	w2 -= w1
    1496:	w2 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1497:	w3 = w2
    1498:	w3 >>= 0xd
    1499:	w6 = w2
    1500:	w6 <<= 0x13
    1501:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1502:	w1 += w4
    1503:	w4 -= w2
    1504:	w4 ^= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1505:	w3 = w4
    1506:	w3 >>= 0x1c
    1507:	w6 = w4
    1508:	w6 <<= 0x4
    1509:	w6 |= w3
; 	__jhash_mix(a, b, c);
    1510:	w2 += w1
    1511:	w1 -= w4
    1512:	w1 ^= w6
; 	c += tuple->nexthdr;
    1513:	w3 = *(u8 *)(r10 - 0x4c)
    1514:	w1 += w3
; 	__jhash_mix(a, b, c);
    1515:	w3 = w2
    1516:	w3 += w5
; 	a += tuple->saddr.p4;
    1517:	w5 = *(u32 *)(r10 - 0x54)
    1518:	w2 += w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1519:	w5 = w1
    1520:	w5 >>= 0x1c
    1521:	w6 = w1
    1522:	w6 <<= 0x4
    1523:	w6 |= w5
; 	__jhash_mix(a, b, c);
    1524:	w2 -= w1
    1525:	w2 ^= w6
; 	b += ((__u32)tuple->dport << 16) | tuple->sport;
    1526:	w3 += w4
; 	return (word << shift) | (word >> ((-shift) & 31));
    1527:	w4 = w2
    1528:	w4 >>= 0x1a
    1529:	w5 = w2
    1530:	w5 <<= 0x6
    1531:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1532:	w1 += w3
    1533:	w3 -= w2
    1534:	w3 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1535:	w4 = w3
    1536:	w4 >>= 0x18
    1537:	w5 = w3
    1538:	w5 <<= 0x8
    1539:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1540:	w2 += w1
    1541:	w1 -= w3
    1542:	w1 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1543:	w4 = w1
    1544:	w4 >>= 0x10
    1545:	w5 = w1
    1546:	w5 <<= 0x10
    1547:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1548:	w3 += w2
    1549:	w2 -= w1
    1550:	w2 ^= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1551:	w4 = w2
    1552:	w4 >>= 0xd
    1553:	w5 = w2
    1554:	w5 <<= 0x13
    1555:	w5 |= w4
; 	__jhash_mix(a, b, c);
    1556:	w1 += w3
    1557:	w3 -= w2
    1558:	w3 ^= w5
    1559:	w2 += w1
    1560:	w4 = w3
    1561:	w4 += w2
; 	return (word << shift) | (word >> ((-shift) & 31));
    1562:	w5 = w4
    1563:	w5 >>= 0x12
    1564:	w6 = w4
    1565:	w6 <<= 0xe
    1566:	w6 |= w5
    1567:	w5 = w3
    1568:	w5 >>= 0x1c
; 	__jhash_mix(a, b, c);
    1569:	w1 -= w3
; 	return (word << shift) | (word >> ((-shift) & 31));
    1570:	w3 <<= 0x4
    1571:	w3 |= w5
; 	__jhash_mix(a, b, c);
    1572:	w1 ^= w3
; 	__jhash_final(a, b, c);
    1573:	w1 ^= w4
    1574:	w1 -= w6
; 	return (word << shift) | (word >> ((-shift) & 31));
    1575:	w3 = w1
    1576:	w3 >>= 0x15
    1577:	w5 = w1
    1578:	w5 <<= 0xb
    1579:	w5 |= w3
; 	a += HASH_INIT6_SEED;
    1580:	w2 += 0xeb9f
; 	__jhash_final(a, b, c);
    1581:	w3 = w1
    1582:	w3 ^= w2
    1583:	w3 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1584:	w2 = w3
    1585:	w2 >>= 0x7
    1586:	w5 = w3
    1587:	w5 <<= 0x19
    1588:	w5 |= w2
; 	__jhash_final(a, b, c);
    1589:	w2 = w3
    1590:	w2 ^= w4
    1591:	w2 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1592:	w4 = w2
    1593:	w4 >>= 0x10
    1594:	w5 = w2
    1595:	w5 <<= 0x10
    1596:	w5 |= w4
; 	__jhash_final(a, b, c);
    1597:	w4 = w2
    1598:	w4 ^= w1
    1599:	w4 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1600:	w1 = w4
    1601:	w1 >>= 0x1c
    1602:	w5 = w4
    1603:	w5 <<= 0x4
    1604:	w5 |= w1
; 	__jhash_final(a, b, c);
    1605:	w1 = w4
    1606:	w1 ^= w3
    1607:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1608:	w3 = w1
    1609:	w3 >>= 0x12
    1610:	w5 = w1
    1611:	w5 <<= 0xe
    1612:	w5 |= w3
; 	__jhash_final(a, b, c);
    1613:	w1 ^= w2
    1614:	w1 -= w5
; 	return (word << shift) | (word >> ((-shift) & 31));
    1615:	w2 = w1
    1616:	w2 >>= 0x8
    1617:	w3 = w1
    1618:	w3 <<= 0x18
    1619:	w3 |= w2
; 	__jhash_final(a, b, c);
    1620:	w1 ^= w4
    1621:	w1 -= w3
; 	index = hash_from_tuple_v6(tuple) % LB_MAGLEV_LUT_SIZE;
    1622:	w1 %= 0x7fed
    1623:	*(u32 *)(r10 - 0x10) = w1
; 	asm volatile("%[index] <<= 2\n\t"
    1624:	r1 <<= 0x2
    1625:	if r1 > 0x1ffb0 goto +0x1 <LBB16_113+0x600>
    1626:	r0 += r1
    1627:	w8 = *(u32 *)(r0 + 0x0)

00000000000032e0 <LBB16_119>:
    1628:	r6 = *(u64 *)(r10 - 0x98)
    1629:	goto +0xd <LBB16_122>

00000000000032f0 <LBB16_120>:
; 	__u16 slot = (get_prandom_u32() % svc->count) + 1;
    1630:	call 0x7
    1631:	w1 = *(u16 *)(r7 + 0x4)
    1632:	w0 %= w1
    1633:	w0 += 0x1
; 	key->backend_slot = slot;
    1634:	*(u16 *)(r10 - 0x76) = w0
    1635:	r2 = r10
    1636:	r2 += -0x88
; 	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
    1637:	r1 = 0x0 ll
    1639:	call 0x1
    1640:	w8 = 0x0
; 	return be ? be->backend_id : 0;
    1641:	if r0 == 0x0 goto +0x1 <LBB16_122>
    1642:	w8 = *(u32 *)(r0 + 0x0)

0000000000003358 <LBB16_122>:
    1643:	*(u32 *)(r10 - 0x48) = w8
    1644:	r2 = r10
    1645:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1646:	r1 = 0x0 ll
    1648:	call 0x1
    1649:	r3 = r8
    1650:	w1 = 0x0
; 			if (backend == NULL)
    1651:	*(u32 *)(r10 - 0xa0) = w1
    1652:	if r0 == 0x0 goto +0x107 <LBB16_169>

00000000000033a8 <LBB16_123>:
    1653:	r1 = 0x0
; 	struct ct_entry entry = { };
    1654:	*(u64 *)(r10 - 0x28) = r1
    1655:	*(u64 *)(r10 - 0x20) = r1
    1656:	*(u64 *)(r10 - 0x18) = r1
    1657:	*(u64 *)(r10 - 0x30) = r1
    1658:	*(u64 *)(r10 - 0x38) = r1
    1659:	*(u64 *)(r10 - 0x48) = r1
; 	entry->rev_nat_index = state->rev_nat_index;
    1660:	w1 = *(u32 *)(r10 - 0xc0)
    1661:	*(u16 *)(r10 - 0x22) = w1
; 		entry->backend_id = state->backend_id;
    1662:	w1 = w3
    1663:	*(u64 *)(r10 - 0x40) = r1
    1664:	w1 = 0x0
; 	entry->src_sec_id = state->src_sec_id;
    1665:	*(u32 *)(r10 - 0x1c) = w1
    1666:	w7 = 0x1
; 	bool is_tcp = tuple->nexthdr == IPPROTO_TCP;
    1667:	w1 = *(u8 *)(r10 - 0x4c)
    1668:	if w1 == 0x6 goto +0x1 <LBB16_125>
    1669:	w7 = 0x0

0000000000003430 <LBB16_125>:
    1670:	w8 = 0x3c
; 	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
    1671:	w7 <<= 0x9
; 	if (tcp) {
    1672:	if w1 != 0x6 goto +0xb <LBB16_129>
; 		entry->seen_non_syn |= !syn;
    1673:	w2 = w7
    1674:	w2 &= 0xffff
    1675:	w2 >>= 0x5
    1676:	w2 ^= 0x10
    1677:	w1 = *(u16 *)(r10 - 0x24)
    1678:	w1 |= w2
; 		if (entry->seen_non_syn) {
    1679:	w2 = w1
    1680:	w2 &= 0x10
    1681:	if w2 == 0x0 goto +0x1 <LBB16_128>
    1682:	w8 = 0x5460

0000000000003498 <LBB16_128>:
; 		entry->seen_non_syn |= !syn;
    1683:	*(u16 *)(r10 - 0x24) = w1

00000000000034a0 <LBB16_129>:
    1684:	*(u64 *)(r10 - 0xd8) = r0
    1685:	*(u64 *)(r10 - 0xf0) = r3
; 	__u32 now = (__u32)bpf_mono_now();
    1686:	call 0x5
    1687:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    1688:	w8 += w0
    1689:	*(u32 *)(r10 - 0x28) = w8
; 	barrier();
    1690:	w7 >>= 0x8
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1691:	w2 = *(u8 *)(r10 - 0x1e)
; 	seen_flags |= accumulated_flags;
    1692:	w1 = w2
    1693:	w1 |= w7
; 		last_report = READ_ONCE(entry->last_tx_report);
    1694:	w3 = *(u32 *)(r10 - 0x18)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1695:	w3 += 0x5
    1696:	if w3 < w0 goto +0x3 <LBB16_131>
    1697:	w3 = w1
    1698:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    1699:	if w2 == w3 goto +0x2 <LBB16_132>

0000000000003520 <LBB16_131>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    1700:	*(u8 *)(r10 - 0x1e) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    1701:	*(u32 *)(r10 - 0x18) = w0

0000000000003530 <LBB16_132>:
    1702:	r1 = 0x1
; 	entry.packets = 1;
    1703:	*(u64 *)(r10 - 0x38) = r1
; 	return ctx->len;
    1704:	w1 = *(u32 *)(r6 + 0x0)
; 	entry.bytes = ctx_full_len(ctx);
    1705:	*(u64 *)(r10 - 0x30) = r1
    1706:	r2 = r10
; 	entry.packets = 1;
    1707:	r2 += -0x70
    1708:	r3 = r10
    1709:	r3 += -0x48
    1710:	w1 = 0x0
; 	err = map_update_elem(map_main, tuple, &entry, 0);
    1711:	*(u32 *)(r10 - 0xa0) = w1
    1712:	r1 = *(u64 *)(r10 - 0xd0)
    1713:	w4 = 0x0
    1714:	call 0x2
    1715:	w7 = w0
    1716:	w9 = 0x0
; 	if (unlikely(err < 0))
    1717:	if w7 s> -0x1 goto +0xe <LBB16_134>
    1718:	r1 = 0x100000001 ll
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    1720:	*(u64 *)(r10 - 0x10) = r1
    1721:	r4 = r10
    1722:	r4 += -0x10
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    1723:	r1 = r6
    1724:	r2 = 0x0 ll
    1726:	r3 = 0xffffffff ll
    1728:	w5 = 0x8
    1729:	call 0x19
    1730:	w9 = -0x9b
    1731:	*(u32 *)(r10 - 0xa0) = w7

0000000000003620 <LBB16_134>:
    1732:	r2 = *(u64 *)(r10 - 0xf0)
    1733:	r3 = *(u64 *)(r10 - 0xd8)
; 		if (IS_ERR(ret))
    1734:	if w7 s< 0x0 goto +0xb5 <LBB16_169>

0000000000003638 <LBB16_149>:
; 	tuple->flags = flags;
    1735:	w1 = *(u32 *)(r10 - 0xc8)
    1736:	*(u8 *)(r10 - 0x4b) = w1
    1737:	r7 = *(u64 *)(r10 - 0xb8)
; 	return svc->flags & SVC_FLAG_AFFINITY;
    1738:	w1 = *(u8 *)(r7 + 0x8)
    1739:	w1 &= 0x10
; 	if (lb6_svc_is_affinity(svc))
    1740:	*(u64 *)(r10 - 0xd8) = r3
    1741:	if w1 == 0x0 goto +0x1f <LBB16_151>
    1742:	r9 = r2
; 	__u32 now = (__u32)bpf_mono_now();
    1743:	call 0x5
    1744:	r1 = 0x0
; 	struct lb6_affinity_key key = {
    1745:	*(u64 *)(r10 - 0x38) = r1
    1746:	*(u64 *)(r10 - 0x40) = r1
    1747:	*(u64 *)(r10 - 0x48) = r1
; 		.rev_nat_id	= svc->rev_nat_index,
    1748:	w1 = *(u16 *)(r7 + 0x6)
; 	struct lb6_affinity_key key = {
    1749:	*(u16 *)(r10 - 0x38) = w1
    1750:	w1 = *(u8 *)(r10 - 0x36)
    1751:	w1 &= 0xfe
    1752:	*(u8 *)(r10 - 0x36) = w1
; 	dst->d2 = src->d2;
    1753:	r1 = *(u64 *)(r10 - 0xe8)
    1754:	*(u64 *)(r10 - 0x40) = r1
; 	dst->d1 = src->d1;
    1755:	r1 = *(u64 *)(r10 - 0xe0)
    1756:	*(u64 *)(r10 - 0x48) = r1
; 	struct lb_affinity_val val = {
    1757:	*(u32 *)(r10 - 0x8) = w9
; 	__u32 now = (__u32)bpf_mono_now();
    1758:	r0 /= 0x3b9aca00
; 		.last_used	= now,
    1759:	r0 <<= 0x20
    1760:	r0 >>= 0x20
; 	struct lb_affinity_val val = {
    1761:	*(u64 *)(r10 - 0x10) = r0
    1762:	w1 = 0x0
    1763:	*(u32 *)(r10 - 0x4) = w1
    1764:	r2 = r10
    1765:	r2 += -0x48
    1766:	r3 = r10
    1767:	r3 += -0x10
; 	map_update_elem(&LB6_AFFINITY_MAP, &key, &val, 0);
    1768:	r1 = 0x0 ll
    1770:	w4 = 0x0
    1771:	call 0x2
    1772:	r3 = *(u64 *)(r10 - 0xd8)

0000000000003768 <LBB16_151>:
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1773:	r1 = *(u64 *)(r3 + 0x8)
    1774:	*(u64 *)(r10 - 0x68) = r1
; 	case  8: jmp_8:  __it_mob(d, s, 64);
    1775:	r1 = *(u64 *)(r3 + 0x0)
    1776:	*(u64 *)(r10 - 0x70) = r1
; 	if (likely(backend->port))
    1777:	w1 = *(u16 *)(r3 + 0x10)
    1778:	if w1 == 0x0 goto +0x1 <LBB16_153>
; 		tuple->sport = backend->port;
    1779:	*(u16 *)(r10 - 0x4e) = w1

00000000000037a0 <LBB16_153>:
; 	return lb6_xlate(ctx, tuple->nexthdr, l3_off, l4_off, key, backend);
    1780:	w1 = *(u8 *)(r10 - 0x4c)
; 	switch (nexthdr) {
    1781:	if w1 == 0x3a goto +0x9 <LBB16_158>
    1782:	if w1 == 0x11 goto +0xd <LBB16_157>
    1783:	w7 = 0x1
    1784:	w8 = 0x0
    1785:	w2 = 0x0
; 	switch (nexthdr) {
    1786:	*(u32 *)(r10 - 0xc8) = w2
    1787:	if w1 != 0x6 goto +0xc <LBB16_160>
    1788:	w1 = 0x10
    1789:	*(u32 *)(r10 - 0xc8) = w1
    1790:	goto +0x3 <LBB16_159>

00000000000037f8 <LBB16_158>:
    1791:	w1 = 0x2
    1792:	*(u32 *)(r10 - 0xc8) = w1
    1793:	w8 = 0x0

0000000000003810 <LBB16_159>:
    1794:	w7 = 0x0
    1795:	goto +0x4 <LBB16_160>

0000000000003820 <LBB16_157>:
    1796:	w1 = 0x6
    1797:	*(u32 *)(r10 - 0xc8) = w1
    1798:	w7 = 0x0
    1799:	w8 = 0x20

0000000000003840 <LBB16_160>:
; 	return ctx_store_bytes(ctx, off + offsetof(struct ipv6hdr, daddr), addr, 16, 0);
    1800:	r1 = r6
    1801:	w2 = 0x18
    1802:	w4 = 0x10
    1803:	w5 = 0x0
    1804:	call 0x9
    1805:	w9 = -0x8d
; 	if (ipv6_store_daddr(ctx, new_dst->addr, l3_off) < 0)
    1806:	if w0 s< 0x0 goto +0x6f <LBB16_170>
; 	if (csum_off.offset) {
    1807:	if w7 != 0x0 goto +0x12 <LBB16_163>
    1808:	r1 = r10
    1809:	r1 += -0x88
; 	return csum_diff_external(from, size_from, to, size_to, seed);
    1810:	w2 = 0x10
    1811:	r3 = *(u64 *)(r10 - 0xd8)
    1812:	w4 = 0x10
    1813:	w5 = 0x0
    1814:	call 0x1c
; 	return l4_csum_replace(ctx, (__u32)(l4_off + csum->offset), from, to, flags | csum->flags);
    1815:	w2 = *(u32 *)(r10 - 0xc8)
    1816:	w1 = *(u32 *)(r10 - 0xb0)
    1817:	w2 += w1
    1818:	w5 = w8
    1819:	w5 |= 0x10
    1820:	r1 = r6
    1821:	w3 = 0x0
    1822:	w4 = w0
    1823:	call 0xb
    1824:	w9 = -0x9a
    1825:	if w0 s< 0x0 goto +0x5c <LBB16_170>

0000000000003910 <LBB16_163>:
; 			   backend->port);
    1826:	r1 = *(u64 *)(r10 - 0xd8)
    1827:	w4 = *(u16 *)(r1 + 0x10)
; 	if (likely(backend_port) && dport != backend_port) {
    1828:	if w4 == 0x0 goto +0x18 <LBB16_168>
    1829:	w3 = *(u16 *)(r10 - 0x78)
; 	if (likely(backend_port) && dport != backend_port) {
    1830:	if w3 == w4 goto +0x16 <LBB16_168>
    1831:	*(u16 *)(r10 - 0x48) = w4
    1832:	w7 = *(u32 *)(r10 - 0xb0)
    1833:	w2 = *(u32 *)(r10 - 0xc8)
; 	return l4_csum_replace(ctx, (__u32)(l4_off + csum->offset), from, to, flags | csum->flags);
    1834:	w2 += w7
    1835:	w8 |= 0x2
    1836:	r1 = r6
    1837:	w5 = w8
    1838:	call 0xb
    1839:	w9 = -0x9a
; 	if (csum_l4_replace(ctx, l4_off, csum_off, old_port, port, sizeof(port)) < 0)
    1840:	if w0 s< 0x0 goto +0xb <LBB16_167>
; 	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
    1841:	w2 = w7
    1842:	w2 += 0x2
    1843:	r3 = r10
    1844:	r3 += -0x48
; 	if (ctx_store_bytes(ctx, l4_off + off, &port, sizeof(port), 0) < 0)
    1845:	r1 = r6
    1846:	w4 = 0x2
    1847:	w5 = 0x0
    1848:	call 0x9
    1849:	w9 = w0
    1850:	w9 s>>= 0x1f
    1851:	w9 &= -0x8d

00000000000039e0 <LBB16_167>:
    1852:	if w9 s< 0x0 goto +0x41 <LBB16_170>

00000000000039e8 <LBB16_168>:
    1853:	w9 = 0x0
    1854:	goto +0x3f <LBB16_170>

00000000000039f8 <LBB16_300>:
; 		new_entry.bytes = bytes;
    1855:	*(u64 *)(r10 - 0x40) = r6
    1856:	r1 = 0x1
; 		new_entry.count = 1;
    1857:	*(u64 *)(r10 - 0x48) = r1
    1858:	r2 = r10
; 		new_entry.bytes = bytes;
    1859:	r2 += -0x70
    1860:	r3 = r10
    1861:	r3 += -0x48
; 		map_update_elem(&METRICS_MAP, &key, &new_entry, 0);
    1862:	r1 = 0x0 ll
    1864:	w4 = 0x0
    1865:	call 0x2

0000000000003a50 <LBB16_301>:
; 	tail_call_static(ctx, CALLS_MAP, index);
    1866:	r1 = r7
    1867:	r2 = 0x0 ll
    1869:	r3 = 0x1
    1870:	call 0xc
    1871:	w9 = 0x2

0000000000003a80 <LBB16_302>:
; }
    1872:	w0 = w9
    1873:	exit

0000000000003a90 <LBB16_144>:
; 	__u16 slot = (get_prandom_u32() % svc->count) + 1;
    1874:	call 0x7
    1875:	r1 = *(u64 *)(r10 - 0xb8)
    1876:	w1 = *(u16 *)(r1 + 0x4)
    1877:	w0 %= w1
    1878:	w0 += 0x1
; 	key->backend_slot = slot;
    1879:	*(u16 *)(r10 - 0x76) = w0
    1880:	r2 = r10
    1881:	r2 += -0x88
; 	return map_lookup_elem(&LB6_SERVICES_MAP_V2, key);
    1882:	r1 = 0x0 ll
    1884:	call 0x1
; 	return be ? be->backend_id : 0;
    1885:	if r0 == 0x0 goto +0x1 <LBB16_146>
    1886:	w7 = *(u32 *)(r0 + 0x0)

0000000000003af8 <LBB16_146>:
    1887:	r1 = r7
    1888:	*(u32 *)(r10 - 0x48) = w1
    1889:	r2 = r10
    1890:	r2 += -0x48
; 	return map_lookup_elem(&LB6_BACKEND_MAP, &backend_id);
    1891:	r1 = 0x0 ll
    1893:	call 0x1
    1894:	w1 = 0x0
    1895:	*(u32 *)(r10 - 0xa0) = w1
    1896:	r6 = *(u64 *)(r10 - 0x98)
; 			if (!backend)
    1897:	if r0 == 0x0 goto +0x12 <LBB16_169>
; 			state->rev_nat_index = svc->rev_nat_index;
    1898:	r1 = *(u64 *)(r10 - 0xb8)
    1899:	w1 = *(u16 *)(r1 + 0x6)
; 	entry = map_lookup_elem(map, tuple);
    1900:	*(u32 *)(r10 - 0xc0) = w1
    1901:	r2 = r10
; 			state->rev_nat_index = svc->rev_nat_index;
    1902:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
    1903:	r1 = *(u64 *)(r10 - 0xd0)
    1904:	r8 = r0
    1905:	call 0x1
    1906:	r3 = r8
    1907:	r2 = r7
    1908:	w1 = 0x0
; 	if (!entry)
    1909:	*(u32 *)(r10 - 0xa0) = w1
    1910:	if r0 == 0x0 goto -0xb0 <LBB16_149>
; 	entry->rev_nat_index = rev_nat_index;
    1911:	w1 = *(u32 *)(r10 - 0xc0)
    1912:	*(u16 *)(r0 + 0x26) = w1
; 	entry->backend_id = backend_id;
    1913:	w1 = w2
    1914:	*(u64 *)(r0 + 0x8) = r1
    1915:	goto -0xb5 <LBB16_149>

0000000000003be0 <LBB16_169>:
; 	tuple->flags = flags;
    1916:	w1 = *(u32 *)(r10 - 0xc8)
    1917:	*(u8 *)(r10 - 0x4b) = w1

0000000000003bf0 <LBB16_170>:
    1918:	r7 = *(u64 *)(r10 - 0xb8)
; 	if (IS_ERR(ret))
    1919:	if w9 s< 0x0 goto -0x62e <LBB16_245>
    1920:	if w9 == 0x2 goto -0x62f <LBB16_245>
    1921:	w1 = 0x0
; 	key.ip6 = *ip6;
    1922:	*(u32 *)(r10 - 0x38) = w1
    1923:	r1 = *(u64 *)(r10 - 0x70)
    1924:	*(u64 *)(r10 - 0x48) = r1
    1925:	r1 = *(u64 *)(r10 - 0x68)
    1926:	*(u64 *)(r10 - 0x40) = r1
    1927:	w1 = 0x2
; 	key.family = ENDPOINT_KEY_IPV6;
    1928:	*(u8 *)(r10 - 0x38) = w1
    1929:	r2 = r10
    1930:	r2 += -0x48
; 	return map_lookup_elem(&ENDPOINTS_MAP, &key);
    1931:	r1 = 0x0 ll
    1933:	call 0x1
; 	if (!backend_local && lb6_svc_is_hostport(svc))
    1934:	if r0 != 0x0 goto +0x6 <LBB16_175>
    1935:	w9 = -0x86
; 	return svc->flags & SVC_FLAG_HOSTPORT;
    1936:	w1 = *(u8 *)(r7 + 0x8)
    1937:	w1 &= 0x8
; 	if (!backend_local && lb6_svc_is_hostport(svc))
    1938:	if w1 != 0x0 goto -0x641 <LBB16_245>
; 				 tuple->nexthdr);
    1939:	w1 = *(u8 *)(r10 - 0x4c)
; 	if (backend_local || !nodeport_uses_dsr6(svc, tuple)) {
    1940:	if w1 == 0x6 goto +0x167 <LBB16_240>

0000000000003ca8 <LBB16_175>:
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1941:	r1 = *(u64 *)(r10 - 0x58)
    1942:	r2 = *(u64 *)(r10 - 0x68)
    1943:	*(u64 *)(r10 - 0x58) = r2
; 	case  8: jmp_8:  __it_mob(d, s, 64);
    1944:	r2 = *(u64 *)(r10 - 0x70)
    1945:	r3 = *(u64 *)(r10 - 0x60)
    1946:	*(u64 *)(r10 - 0x70) = r3
    1947:	*(u64 *)(r10 - 0x60) = r2
; 	case 16: jmp_16: __it_mob(d, s, 64); fallthrough;
    1948:	*(u64 *)(r10 - 0x68) = r1
; 	tmp = tuple->sport;
    1949:	w1 = *(u16 *)(r10 - 0x4e)
; 	tuple->sport = tuple->dport;
    1950:	w2 = *(u16 *)(r10 - 0x50)
    1951:	*(u16 *)(r10 - 0x4e) = w2
; 	tuple->dport = tmp;
    1952:	*(u16 *)(r10 - 0x50) = w1
    1953:	r7 = 0x0 ll
; 	if (tuple->nexthdr == IPPROTO_TCP)
    1955:	w2 = *(u8 *)(r10 - 0x4c)
    1956:	if w2 == 0x6 goto +0x2 <LBB16_177>
    1957:	r7 = 0x0 ll

0000000000003d38 <LBB16_177>:
    1959:	*(u64 *)(r10 - 0xb8) = r0
    1960:	w1 = 0x0
; 	tuple->flags = ct_lookup_select_tuple_type(dir, scope);
    1961:	*(u8 *)(r10 - 0x4b) = w1
; 	union tcp_flags tcp_flags = { .value = 0 };
    1962:	*(u32 *)(r10 - 0x48) = w1
    1963:	w9 = 0x0
    1964:	*(u32 *)(r10 - 0xc8) = w2
; 	if (is_tcp) {
    1965:	if w2 != 0x6 goto +0x12 <LBB16_181>
    1966:	w2 = *(u32 *)(r10 - 0xb0)
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
    1967:	w2 += 0xc
    1968:	r3 = r10
    1969:	r3 += -0x48
; 	return ctx_load_bytes(ctx, l4_off + 12, flags, 2);
    1970:	r1 = r6
    1971:	w4 = 0x2
    1972:	call 0x1a
    1973:	w2 = -0x87
    1974:	w3 = 0x1
    1975:	w8 = 0x0
; 		if (l4_load_tcp_flags(ctx, l4_off, &tcp_flags) < 0)
    1976:	if w0 s< 0x0 goto +0xa5 <LBB16_209>
; 		action = ct_tcp_select_action(tcp_flags);
    1977:	w9 = *(u32 *)(r10 - 0x48)
; 	if (unlikely(flags.value & (TCP_FLAG_RST | TCP_FLAG_FIN)))
    1978:	w1 = w9
    1979:	w1 &= 0x500
    1980:	w9 >>= 0x9
    1981:	w9 &= 0x1
    1982:	if w1 == 0x0 goto +0x1 <LBB16_181>
    1983:	w9 = 0x2

0000000000003e00 <LBB16_181>:
; 		ret = __ct_lookup(map, ctx, tuple, action, dir, ct_entry_types,
    1984:	w1 = *(u32 *)(r10 - 0x48)
; 	entry = map_lookup_elem(map, tuple);
    1985:	*(u32 *)(r10 - 0xb0) = w1
    1986:	r2 = r10
    1987:	r2 += -0x70
; 	entry = map_lookup_elem(map, tuple);
    1988:	r1 = r7
    1989:	call 0x1
    1990:	r7 = r0
    1991:	w8 = 0x0
    1992:	w3 = 0x0
    1993:	w2 = 0x0
; 	if (entry) {
    1994:	if r7 == 0x0 goto +0x93 <LBB16_209>
; 	    entry->node_port && entry->rev_nat_index) {
    1995:	w1 = *(u16 *)(r7 + 0x24)
    1996:	w4 = w1
    1997:	w4 &= 0x20
    1998:	if w4 == 0x0 goto +0x8f <LBB16_209>
    1999:	w4 = *(u16 *)(r7 + 0x26)
; 	if ((ct_entry_types & CT_ENTRY_NODEPORT) &&
    2000:	if w4 == 0x0 goto +0x8d <LBB16_209>
; 		if (!state || !state->rev_nat_index)
    2001:	w5 = *(u32 *)(r10 - 0xc0)
    2002:	w5 &= 0xffff
    2003:	if w5 == 0x0 goto +0x1 <LBB16_186>
; 		if (entry->rev_nat_index == state->rev_nat_index)
    2004:	if w4 != w5 goto +0x89 <LBB16_209>

0000000000003ea8 <LBB16_186>:
; 	return !entry->rx_closing || !entry->tx_closing;
    2005:	w2 = w1
    2006:	w2 &= 0x3
    2007:	w8 = *(u32 *)(r10 - 0xb0)
; 		if (ct_entry_alive(entry))
    2008:	if w2 == 0x3 goto +0x20 <LBB16_193>
    2009:	w3 = 0x3c
; 	if (tcp) {
    2010:	w2 = *(u32 *)(r10 - 0xc8)
    2011:	if w2 != 0x6 goto +0x9 <LBB16_190>
; 		entry->seen_non_syn |= !syn;
    2012:	w2 = w8
    2013:	w2 ^= -0x1
    2014:	w2 >>= 0x5
    2015:	w2 &= 0x10
    2016:	w1 |= w2
    2017:	*(u16 *)(r7 + 0x24) = w1
; 		if (entry->seen_non_syn) {
    2018:	w1 &= 0x10
    2019:	if w1 == 0x0 goto +0x1 <LBB16_190>
    2020:	w3 = 0x5460

0000000000003f28 <LBB16_190>:
    2021:	w8 = w3
; 	__u32 now = (__u32)bpf_mono_now();
    2022:	call 0x5
    2023:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2024:	w8 += w0
    2025:	*(u32 *)(r7 + 0x20) = w8
    2026:	w8 = *(u32 *)(r10 - 0xb0)
; 	barrier();
    2027:	w3 = w8
    2028:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2029:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2030:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2031:	w1 = w2
    2032:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    2033:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2034:	w3 += 0x5
    2035:	if w3 < w0 goto +0x3 <LBB16_192>
    2036:	w3 = w1
    2037:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2038:	if w2 == w3 goto +0x2 <LBB16_193>

0000000000003fb8 <LBB16_192>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2039:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2040:	*(u32 *)(r7 + 0x30) = w0

0000000000003fc8 <LBB16_193>:
    2041:	r1 = 0x1
; 		__sync_fetch_and_add(&entry->packets, 1);
    2042:	lock *(u64 *)(r7 + 0x10) += r1
; 	return ctx->len;
    2043:	w1 = *(u32 *)(r6 + 0x0)
; 		__sync_fetch_and_add(&entry->bytes, ctx_full_len(ctx));
    2044:	lock *(u64 *)(r7 + 0x18) += r1
; 		switch (action) {
    2045:	if w9 == 0x2 goto +0x2f <LBB16_202>
    2046:	w4 = 0x0
; 		switch (action) {
    2047:	if w9 != 0x1 goto +0x4b <LBB16_208>
; 	return entry->tx_closing || entry->rx_closing;
    2048:	w1 = *(u16 *)(r7 + 0x24)
    2049:	w2 = w1
    2050:	w2 &= 0x3
; 			if (unlikely(ct_entry_closing(entry))) {
    2051:	if w2 == 0x0 goto +0x47 <LBB16_208>
    2052:	w2 = 0x0
; 	entry->tx_flags_seen = 0;
    2053:	*(u16 *)(r7 + 0x2a) = w2
; 				entry->seen_non_syn = false;
    2054:	w1 &= 0xffec
    2055:	*(u16 *)(r7 + 0x24) = w1
    2056:	w9 = 0x3c
; 	if (tcp) {
    2057:	w2 = *(u32 *)(r10 - 0xc8)
    2058:	if w2 != 0x6 goto +0x8 <LBB16_199>
; 		entry->seen_non_syn |= !syn;
    2059:	w2 = *(u32 *)(r10 - 0xb0)
    2060:	w2 ^= -0x1
    2061:	w2 >>= 0x5
    2062:	w2 &= 0x10
    2063:	w1 |= w2
    2064:	*(u16 *)(r7 + 0x24) = w1
    2065:	if w2 == 0x0 goto +0x1 <LBB16_199>
    2066:	w9 = 0x5460

0000000000004098 <LBB16_199>:
; 	__u32 now = (__u32)bpf_mono_now();
    2067:	call 0x5
    2068:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2069:	w9 += w0
    2070:	*(u32 *)(r7 + 0x20) = w9
; 	barrier();
    2071:	w3 = *(u32 *)(r10 - 0xb0)
    2072:	w3 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2073:	w3 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2074:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2075:	w1 = w2
    2076:	w1 |= w3
; 		last_report = READ_ONCE(entry->last_tx_report);
    2077:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2078:	w3 += 0x5
    2079:	r6 = *(u64 *)(r10 - 0x98)
    2080:	w8 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2081:	if w3 < w0 goto +0x6 <LBB16_201>
    2082:	w4 = w1
    2083:	w4 &= 0xff
    2084:	r5 = r2
    2085:	w3 = 0x0
    2086:	w2 = 0x0
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2087:	if w5 == w4 goto +0x36 <LBB16_209>

0000000000004140 <LBB16_201>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2088:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2089:	*(u32 *)(r7 + 0x30) = w0
; 	barrier();
    2090:	w3 = 0x0
    2091:	w2 = 0x0
    2092:	goto +0x31 <LBB16_209>

0000000000004168 <LBB16_202>:
; 				    (seen_flags.value & TCP_FLAG_RST)) {
    2093:	w2 = w8
    2094:	w2 &= 0x400
    2095:	w1 = 0x2
; 				if (!ct_entry_seen_both_syns(entry) &&
    2096:	if w2 == 0x0 goto +0x1 <LBB16_204>
    2097:	w1 = 0x3

0000000000004190 <LBB16_204>:
    2098:	w2 = *(u16 *)(r7 + 0x24)
; 				if (!ct_entry_seen_both_syns(entry) &&
    2099:	w2 |= w1
    2100:	*(u16 *)(r7 + 0x24) = w2
    2101:	w4 = 0x100
; 	return !entry->rx_closing || !entry->tx_closing;
    2102:	w2 &= 0x3
; 			if (ct_entry_alive(entry))
    2103:	if w2 != 0x3 goto +0x13 <LBB16_208>
; 	__u32 now = (__u32)bpf_mono_now();
    2104:	call 0x5
    2105:	w4 = 0x100
; 	__u32 now = (__u32)bpf_mono_now();
    2106:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2107:	w1 = w0
    2108:	w1 += 0xa
    2109:	*(u32 *)(r7 + 0x20) = w1
; 	barrier();
    2110:	w8 >>= 0x8
; 	seen_flags |= accumulated_flags;
    2111:	w8 &= 0x2
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2112:	w2 = *(u8 *)(r7 + 0x2a)
; 	seen_flags |= accumulated_flags;
    2113:	w1 = w2
    2114:	w1 |= w8
; 		last_report = READ_ONCE(entry->last_tx_report);
    2115:	w3 = *(u32 *)(r7 + 0x30)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2116:	w3 += 0x5
    2117:	if w3 < w0 goto +0x3 <LBB16_207>
    2118:	w3 = w1
    2119:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2120:	if w2 == w3 goto +0x2 <LBB16_208>

0000000000004248 <LBB16_207>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2121:	*(u8 *)(r7 + 0x2a) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2122:	*(u32 *)(r7 + 0x30) = w0

0000000000004258 <LBB16_208>:
; 		state->loopback = entry->lb_loopback;
    2123:	w2 = *(u16 *)(r7 + 0x24)
    2124:	w1 = w2
    2125:	w1 >>= 0x3
    2126:	w8 = w1
    2127:	w8 &= 0x1
    2128:	w8 |= w4
; 		state->dsr_internal = entry->dsr_internal;
    2129:	w3 = w2
    2130:	w3 >>= 0x5
    2131:	w3 &= 0x4
    2132:	w8 |= w3
; 		state->proxy_redirect = entry->proxy_redirect;
    2133:	w2 >>= 0x2
    2134:	w2 &= 0x10
; 		state->from_l7lb = entry->from_l7lb;
    2135:	w8 |= w2
; 		state->from_tunnel = entry->from_tunnel;
    2136:	w1 &= 0xa0
    2137:	w8 |= w1
    2138:	w2 = 0x1
    2139:	w3 = 0x0
; 	state->rev_nat_index = entry->rev_nat_index;
    2140:	w1 = *(u16 *)(r7 + 0x26)
    2141:	*(u32 *)(r10 - 0xc0) = w1

00000000000042f0 <LBB16_209>:
    2142:	w7 = 0x0
    2143:	w9 = w2
; 		if (ret < 0)
    2144:	if w3 != 0x0 goto +0x99 <LBB16_239>
; 		switch (ret) {
    2145:	if w2 == 0x1 goto +0x69 <LBB16_226>
    2146:	w9 = -0xa3
; 		switch (ret) {
    2147:	if w2 != 0x0 goto +0x96 <LBB16_239>
; 			ct_state.ifindex = (__u16)THIS_INTERFACE_IFINDEX;
    2148:	r1 = 0x0 ll
    2150:	w2 = *(u32 *)(r1 + 0x0)
; 	if (tuple->nexthdr == IPPROTO_TCP)
    2151:	w1 = *(u8 *)(r10 - 0x4c)
    2152:	r3 = 0x0
; 	struct ct_entry entry = { };
    2153:	*(u64 *)(r10 - 0x20) = r3
    2154:	*(u64 *)(r10 - 0x28) = r3
    2155:	*(u64 *)(r10 - 0x18) = r3
    2156:	*(u64 *)(r10 - 0x30) = r3
    2157:	*(u64 *)(r10 - 0x38) = r3
    2158:	*(u64 *)(r10 - 0x40) = r3
    2159:	*(u64 *)(r10 - 0x48) = r3
    2160:	w3 = 0xa
; 	entry->src_sec_id = state->src_sec_id;
    2161:	*(u32 *)(r10 - 0x1c) = w3
; 	entry->rev_nat_index = state->rev_nat_index;
    2162:	w3 = *(u32 *)(r10 - 0xc0)
    2163:	*(u16 *)(r10 - 0x22) = w3
; 		entry->ifindex = state->ifindex;
    2164:	*(u16 *)(r10 - 0x20) = w2
    2165:	r2 = 0x0 ll
    2167:	if w1 == 0x6 goto +0x2 <LBB16_214>
    2168:	r2 = 0x0 ll

00000000000043d0 <LBB16_214>:
    2170:	*(u64 *)(r10 - 0x98) = r2
; 		entry->proxy_redirect = state->proxy_redirect;
    2171:	w2 = w8
    2172:	w2 <<= 0x2
    2173:	w2 &= 0x40
; 		entry->lb_loopback = state->loopback;
    2174:	w3 = w8
    2175:	w3 <<= 0x3
; 		entry->from_l7lb = state->from_l7lb;
    2176:	w4 = w3
    2177:	w4 &= 0x100
; 		entry->proxy_redirect = state->proxy_redirect;
    2178:	w4 |= w2
; 		entry->from_tunnel = state->from_tunnel;
    2179:	w3 &= 0x408
; 		entry->dsr_internal = state->dsr_internal;
    2180:	w8 <<= 0x5
    2181:	w8 &= 0x80
; 		entry->from_tunnel = state->from_tunnel;
    2182:	w8 |= w3
; 		entry->lb_loopback = state->loopback;
    2183:	w2 = *(u16 *)(r10 - 0x24)
    2184:	w2 &= -0x5e9
; 		entry->from_tunnel = state->from_tunnel;
    2185:	w8 |= w2
    2186:	w8 |= w4
    2187:	w7 = 0x1
; 	if (tuple->nexthdr == IPPROTO_TCP)
    2188:	if w1 == 0x6 goto +0x1 <LBB16_216>
    2189:	w7 = 0x0

0000000000004470 <LBB16_216>:
    2190:	w9 = 0x3c
; 	seen_flags.value |= is_tcp ? TCP_FLAG_SYN : 0;
    2191:	w7 <<= 0x9
; 		entry->from_l7lb = state->from_l7lb;
    2192:	w8 |= 0x20
    2193:	*(u16 *)(r10 - 0x24) = w8
; 	if (tcp) {
    2194:	if w1 != 0x6 goto +0xa <LBB16_220>
; 		entry->seen_non_syn |= !syn;
    2195:	w1 = w7
    2196:	w1 &= 0xffff
    2197:	w1 >>= 0x5
    2198:	w1 ^= 0x10
    2199:	w8 |= w1
; 		if (entry->seen_non_syn) {
    2200:	w1 = w8
    2201:	w1 &= 0x10
    2202:	if w1 == 0x0 goto +0x1 <LBB16_219>
    2203:	w9 = 0x5460

00000000000044e0 <LBB16_219>:
; 		entry->seen_non_syn |= !syn;
    2204:	*(u16 *)(r10 - 0x24) = w8

00000000000044e8 <LBB16_220>:
; 	__u32 now = (__u32)bpf_mono_now();
    2205:	call 0x5
    2206:	r0 /= 0x3b9aca00
; 	WRITE_ONCE(entry->lifetime, now + lifetime);
    2207:	w9 += w0
    2208:	*(u32 *)(r10 - 0x28) = w9
; 	barrier();
    2209:	w7 >>= 0x8
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2210:	w2 = *(u8 *)(r10 - 0x1e)
; 	seen_flags |= accumulated_flags;
    2211:	w1 = w2
    2212:	w1 |= w7
; 		last_report = READ_ONCE(entry->last_tx_report);
    2213:	w3 = *(u32 *)(r10 - 0x18)
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2214:	w3 += 0x5
    2215:	if w3 < w0 goto +0x3 <LBB16_222>
    2216:	w3 = w1
    2217:	w3 &= 0xff
; 	if (last_report + bpf_sec_to_mono(CT_REPORT_INTERVAL) < now ||
    2218:	if w2 == w3 goto +0x2 <LBB16_223>

0000000000004558 <LBB16_222>:
; 			WRITE_ONCE(entry->tx_flags_seen, seen_flags);
    2219:	*(u8 *)(r10 - 0x1e) = w1
; 			WRITE_ONCE(entry->last_tx_report, now);
    2220:	*(u32 *)(r10 - 0x18) = w0

0000000000004568 <LBB16_223>:
    2221:	r1 = 0x1
; 	entry.packets = 1;
    2222:	*(u64 *)(r10 - 0x38) = r1
; 	return ctx->len;
    2223:	w1 = *(u32 *)(r6 + 0x0)
; 	entry.bytes = ctx_full_len(ctx);
    2224:	*(u64 *)(r10 - 0x30) = r1
    2225:	r2 = r10
; 	entry.packets = 1;
    2226:	r2 += -0x70
    2227:	r3 = r10
    2228:	r3 += -0x48
    2229:	w7 = 0x0
; 	err = map_update_elem(map_main, tuple, &entry, 0);
    2230:	r1 = *(u64 *)(r10 - 0x98)
    2231:	w4 = 0x0
    2232:	call 0x2
    2233:	w8 = w0
    2234:	w9 = 0x0
; 	if (unlikely(err < 0))
    2235:	if w8 s> -0x1 goto +0xe <LBB16_225>
    2236:	r1 = 0x100000001 ll
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    2238:	*(u64 *)(r10 - 0x10) = r1
    2239:	r4 = r10
    2240:	r4 += -0x10
; 	SEND_SIGNAL(ctx, SIGNAL_CT_FILL_UP, proto, proto);
    2241:	r1 = r6
    2242:	r2 = 0x0 ll
    2244:	r3 = 0xffffffff ll
    2246:	w5 = 0x8
    2247:	call 0x19
    2248:	w9 = -0x9b
    2249:	*(u32 *)(r10 - 0xa0) = w8

0000000000004650 <LBB16_225>:
; 			if (IS_ERR(ret))
    2250:	if w8 s< 0x0 goto +0x2f <LBB16_239>

0000000000004658 <LBB16_226>:
    2251:	r1 = 0x0
; 	union macaddr smac = {}, *mac;
    2252:	*(u64 *)(r10 - 0x48) = r1
; DEFINE_FUNC_CTX_POINTER(data_end)
    2253:	w1 = *(u32 *)(r6 + 0x50)
; DEFINE_FUNC_CTX_POINTER(data)
    2254:	w7 = *(u32 *)(r6 + 0x4c)
    2255:	w9 = -0x86
; 	if (data + tot_len > data_end)
    2256:	r2 = r7
    2257:	r2 += 0x28
; 	if (!revalidate_data(ctx, &data, &data_end, &ip6))
    2258:	if r2 > r1 goto +0x1f <LBB16_234>
    2259:	r3 = r10
    2260:	r3 += -0x48
; 	return ctx_load_bytes(ctx, off + ETH_ALEN, mac, ETH_ALEN);
    2261:	r1 = r6
    2262:	w2 = 0x6
    2263:	w4 = 0x6
    2264:	call 0x1a
; 	if (eth_load_saddr(ctx, smac.addr, 0) < 0)
    2265:	if w0 s< 0x0 goto +0x18 <LBB16_234>
; 	mac = map_lookup_elem(&NODEPORT_NEIGH6, &ip6->saddr);
    2266:	r7 += 0x8
    2267:	r1 = 0x0 ll
    2269:	r2 = r7
    2270:	call 0x1
; 	if (!mac || eth_addrcmp(mac, &smac)) {
    2271:	if r0 == 0x0 goto +0x8 <LBB16_232>
; 	tmp = a->p1 - b->p1;
    2272:	w1 = *(u32 *)(r0 + 0x0)
    2273:	w2 = *(u32 *)(r10 - 0x48)
    2274:	w1 -= w2
; 	if (!tmp)
    2275:	if w1 != 0x0 goto +0x3 <LBB16_231>
; 		tmp = a->p2 - b->p2;
    2276:	w1 = *(u16 *)(r0 + 0x4)
    2277:	w2 = *(u16 *)(r10 - 0x44)
    2278:	w1 -= w2

0000000000004738 <LBB16_231>:
; 	if (!mac || eth_addrcmp(mac, &smac)) {
    2279:	if w1 == 0x0 goto +0x9 <LBB16_233>

0000000000004740 <LBB16_232>:
    2280:	r3 = r10
    2281:	r3 += -0x48
; 		int ret = map_update_elem(&NODEPORT_NEIGH6, &ip6->saddr,
    2282:	r1 = 0x0 ll
    2284:	r2 = r7
    2285:	w4 = 0x0
    2286:	call 0x2
    2287:	w9 = w0
    2288:	if w9 s< 0x0 goto +0x1 <LBB16_234>

0000000000004788 <LBB16_233>:
    2289:	w9 = 0x0

0000000000004790 <LBB16_234>:
    2290:	w7 = 0x1
; 		if (ret < 0)
    2291:	if w9 s> -0x1 goto +0x1 <LBB16_236>
    2292:	w7 = 0x0

00000000000047a8 <LBB16_236>:
; 		if (ret < 0)
    2293:	r1 = *(u64 *)(r10 - 0xb8)
    2294:	if r1 == 0x0 goto +0x3 <LBB16_239>
    2295:	if w9 s< 0x0 goto +0x2 <LBB16_239>
    2296:	w7 = 0x0
    2297:	w9 = 0x0

00000000000047d0 <LBB16_239>:
    2298:	w7 &= 0x1
    2299:	if w7 == 0x0 goto -0x7aa <LBB16_245>

00000000000047e0 <LBB16_240>:
    2300:	w1 = 0x0
; 	ctx->queue_mapping = aggregate;
    2301:	*(u32 *)(r6 + 0xc) = w1
; 				 tuple->nexthdr);
    2302:	w2 = *(u8 *)(r10 - 0x4c)
; 	if (nodeport_uses_dsr6(svc, tuple)) {
    2303:	if w2 != 0x6 goto +0x12 <LBB16_242>
; 		ctx_store_meta(ctx, CB_PORT, key->dport);
    2304:	w1 = *(u16 *)(r10 - 0x78)
; 	ctx->cb[off] = data;
    2305:	*(u32 *)(r6 + 0x30) = w1
; 	ctx_store_meta(ctx, off, addr->p1);
    2306:	w1 = *(u32 *)(r10 - 0x88)
; 	ctx->cb[off] = data;
    2307:	*(u32 *)(r6 + 0x34) = w1
; 	ctx_store_meta(ctx, off + 1, addr->p2);
    2308:	w1 = *(u32 *)(r10 - 0x84)
; 	ctx->cb[off] = data;
    2309:	*(u32 *)(r6 + 0x38) = w1
; 	ctx_store_meta(ctx, off + 2, addr->p3);
    2310:	w1 = *(u32 *)(r10 - 0x80)
; 	ctx->cb[off] = data;
    2311:	*(u32 *)(r6 + 0x3c) = w1
; 	ctx_store_meta(ctx, off + 3, addr->p4);
    2312:	w1 = *(u32 *)(r10 - 0x7c)
; 	ctx->cb[off] = data;
    2313:	*(u32 *)(r6 + 0x40) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
    2314:	r1 = r6
    2315:	r2 = 0x0 ll
    2317:	r3 = 0x15
    2318:	call 0xc
    2319:	w9 = -0x8c
    2320:	w1 = 0x15
    2321:	goto -0x7c1 <LBB16_244>

0000000000004890 <LBB16_242>:
; 	ctx->cb[off] = data;
    2322:	*(u32 *)(r6 + 0x34) = w1
; 	tail_call_static(ctx, CALLS_MAP, index);
    2323:	r1 = r6
    2324:	r2 = 0x0 ll
    2326:	r3 = 0x10
    2327:	call 0xc
    2328:	w9 = -0x8c
    2329:	w1 = 0x10
    2330:	goto -0x7ca <LBB16_244>


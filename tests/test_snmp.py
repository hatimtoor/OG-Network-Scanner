from netscope.enrich import snmp


def test_oid_roundtrip():
    for oid in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.2.2.1.10.1"):
        tag, value = snmp._parse(snmp._enc_oid(oid))[0]
        assert tag == 0x06
        assert snmp._decode_oid(value) == oid


def test_build_get_is_valid_ber():
    pkt = snmp.build_get(["1.3.6.1.2.1.1.5.0"], community="public")
    assert pkt[0] == 0x30  # SEQUENCE
    nodes = snmp._parse(pkt)
    assert nodes and nodes[0][0] == 0x30
    # GetNext uses a different PDU tag
    nxt = snmp.build_get(["1.3.6.1.2.1.1.5.0"], pdu_tag=0xA1)
    assert nxt != pkt


def test_decode_response_varbinds():
    oid = "1.3.6.1.2.1.1.5.0"
    varbind = snmp._tlv(0x30, snmp._enc_oid(oid) + snmp._tlv(0x04, b"router1"))
    pdu_body = snmp._enc_int(1) + snmp._enc_int(0) + snmp._enc_int(0) + snmp._tlv(0x30, varbind)
    pdu = snmp._tlv(0xA2, pdu_body)  # GetResponse
    msg = snmp._enc_int(1) + snmp._tlv(0x04, b"public") + pdu
    packet = snmp._tlv(0x30, msg)

    result = snmp._collect_varbinds(snmp._parse(packet))
    assert result.get(oid) == "router1"


def test_decode_integer_value():
    assert snmp._decode_value(0x02, (500).to_bytes(2, "big")) == "500"
    assert snmp._decode_value(0x41, (12345).to_bytes(2, "big")) == "12345"

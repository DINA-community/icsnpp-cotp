# @TEST-DOC: Test Zeek parsing a trace file through the cotp analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/cotp.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
#
# @TEST-EXEC: zeek -Cr ${TRACES}/cotp2.pcapng ${PACKAGE} %INPUT >output2
# @TEST-EXEC: btest-diff output2
#
# @TEST-EXEC: zeek -Cr ${TRACES}/s7comm_downloading_block_db1.pcap ${PACKAGE} %INPUT >s7_1
# @TEST-EXEC: btest-diff s7_1


event zeek_init() &priority=5 {
    # the script of tpkt is not loaded even if the tpkt plugin is installed
    Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
}

event cotp::tpdu(c: connection, is_orig: bool, calling_tsap: string, called_tsap: string, _type: cotp::TpduType, class: int) {
  print(fmt("Testing cotp: [orig_h=%s, orig_p=%s, resp_h=%s, resp_p=%s] %s | %s | %d | %d",
	    c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, calling_tsap, called_tsap, _type, class));
}

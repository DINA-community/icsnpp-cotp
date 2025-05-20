# @TEST-DOC: Check dependency to TPKT
#
# This is necessary, otherwise the trace test will fail
# @TEST-EXEC: zeek -NN | grep -Eqi 'ANALYZER_TPKT'

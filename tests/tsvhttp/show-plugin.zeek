# @TEST-EXEC: zeek -NN Zeek::TsvHttp |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output

# @TEST-EXEC: bro -NN Zeek::ZsonHttp |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output

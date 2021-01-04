echo -e "\nUse Wrk\n"

wrk -t10 -c200 -d10s http://127.0.0.1:4399/ > wrk.bench
cat wrk.bench 1>&2

echo -e "\nDone.\n"

sleep 5

echo -e "\nUse ab\n"

echo -e "\nCommon scene\n"
ab -c 50 -n 1500 http://127.0.0.1:4399/ > common.bench
cat common.bench 1>&2

sleep 5

echo -e "\nConnection: keep-alive\n"
ab -k -c 100 -n 50000 http://127.0.0.1:4399/ > keep-alive.bench
cat keep-alive.bench 1>&2

sleep 5

echo -e "\nPost with body\n"
dd if=/dev/urandom of=test_body bs=1024 count=1 2> /dev/null
ab -c 5 -n 200 -p test_body http://127.0.0.1:4399/echo > post-body.bench
cat post-body.bench 1>&2

echo -e "\nClear temp files\n"
rm -rf test_body *.bench

echo "Done."

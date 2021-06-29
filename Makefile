.PHONY: init clean
init:
	git submodule update
	cd ./third_party/capstone && CAPSTONE_ARCHS=x86 ./make.sh
clean:
	rm -rf ./third_party/capstone
	rm -rf .git/modules/third_party/capstone
	mkdir ./third_party/capstone
	git gc
diet:
	cd ./third_party/capstone \
		&& make clean \
		&& CAPSTONE_ARCHS=x86 CAPSTONE_DIET=yes ./make.sh

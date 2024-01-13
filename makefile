APP_NAME = "cert-tools"
DATE_TIME = $(shell date +"%Y-%m-%d_%H_%M_%S")
.PHONY: release
release:
	@echo "构建"
	rm -rf ./release
	mkdir ./release
	@printf "\033[1;40;32m%s\033[0m\n" "--------------------------------------------"
	@printf "\033[1;40;32m%s\033[0m\n" "构建amd64包"
	env GOOS=linux GOARCH=amd64 go build -o ./release/${APP_NAME}-amd64
	@printf "\033[1;40;32m%s\033[0m\n" "--------------------------------------------"
	@printf "\033[1;40;32m%s\033[0m\n" "构建arm64包"
	env GOOS=linux GOARCH=arm64 go build -o ./release/${APP_NAME}-arm64
	tar -czf ${APP_NAME}-release-${DATE_TIME}.tar.gz release
	rm -rf ./release


clean:
	@echo "清理"
	rm -rf ./release ./${APP_NAME}-release-*.tar.gz ${APP_NAME} tmp.*
	rm -rf *crt *key *p12

.PHONY: test
test: clean
	go build -o ${APP_NAME}
	# ./${APP_NAME} -f ./certs.yaml
	./${APP_NAME} -f ./certs.yaml -p12
	./${APP_NAME} -o yaml > tmp.yaml
	./${APP_NAME} -o toml > tmp.toml

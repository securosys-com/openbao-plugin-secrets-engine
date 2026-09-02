#!/bin/bash
cd ..
echo "Build ${ARTIFACT_NAME} in ${DOCKER_OS}_${DOCKER_ARCH}"; 
    cd /src
    CGO_ENABLED=0 go build -o builds/securosys-hsm cmd/securosys-hsm/main.go; 
	cd builds; 
    shasum -a 256 securosys-hsm > securosys-hsm_SHA256SUM; 
    zip -9 ${ARTIFACT_NAME}_${DOCKER_OS}_${DOCKER_ARCH}.zip securosys-hsm securosys-hsm_SHA256SUM; 
    shasum -a 256 ${ARTIFACT_NAME}_${DOCKER_OS}_${DOCKER_ARCH}.zip >> ${ARTIFACT_NAME}_SHA256SUMS; 
    cd ..; 
    rm builds/securosys-hsm; 
    rm builds/securosys-hsm_SHA256SUM;
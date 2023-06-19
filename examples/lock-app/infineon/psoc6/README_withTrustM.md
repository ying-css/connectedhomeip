# Build Matter PSoC6 Lock Example with Optiga Trust M

## Optiga Trust M host Library Patch:

The example uses the optiga-trust-m host lib which is a submodule located at
/third_party/infineon/trustm/optiga-trust-m. To apply the patch which is
situated in /third_party/infineon/trustm by runing the shell script
apply_patch.sh located at the same location: 

​	`$ cd third_party/infineon/trustm`
​	`$ ./apply_patch.sh`

## Building

-   Set the following flags in CHIPCryptoPALHsm_config.h which is located in
    /src/crypto/hsm/CHIPCryptoPALHsm_config.h :
    `ENABLE_HSM_SPAKE_VERIFIER 0`
    `ENABLE_HSM_SPAKE_PROVER 0`
    `ENABLE_HSM_GENERATE_EC_KEY 1`
    `ENABLE_HSM_PBKDF2_SHA256 0` 
    `ENABLE_HSM_HKDF_SHA256 1`
    `ENABLE_HSM_HMAC_SHA256 0` 
    
-   Follow the steps to build: 
    `$ cd examples/lock-app/infineon/psoc6`
    `$ source third_party/conenctedhomeip/scripts/activate.sh`
    `$ export PSOC6_BOARD=CY8CKIT-062S2-43012`
    `$ gn gen out/debug --args="chip_enable_trustm=true chip_enable_trustm_da=true"`
    `$ ninja -C out/debug`

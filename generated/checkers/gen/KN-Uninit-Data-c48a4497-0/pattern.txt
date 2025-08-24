## Bug Pattern

Ignoring the return value of a function that populates an out-parameter and instead using/freeing the out-parameter directly. Specifically, calling request_firmware(&fw, ...) and then checking or releasing fw without verifying the function’s return code. In configurations where request_firmware() fails or is a stub that doesn’t initialize the out-pointer, fw remains uninitialized, leading to use of an uninitialized pointer and invalid release:

const struct firmware *fw;
request_firmware(&fw, file, dev);
if (!fw) {            // fw may be uninitialized if request_firmware() failed/stubbed
    release_firmware(fw);  // invalid free on uninitialized pointer
    ...
}

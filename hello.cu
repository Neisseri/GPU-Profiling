#include <cstdio>

__global__ void helloFromGPU() {
  printf("block index: (%d, %d, %d); thread index: (%d, %d, %d)\n", blockIdx.x,
         blockIdx.y, blockIdx.z, threadIdx.x, threadIdx.y, threadIdx.z);
  (void)0;
}

int main() {
  printf("Hello, World!\n");

  helloFromGPU<<<2, 3>>>();
  cudaDeviceSynchronize();
  return 0;
}

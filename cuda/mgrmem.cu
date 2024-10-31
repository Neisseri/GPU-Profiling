#include <cstdio>

__global__ void product(const double *x, const double *y, double *z, int n) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) {
    z[i] = x[i] * y[i];
  }
}

constexpr int N = 128;
constexpr int BLOCK_SIZE = 32;

__managed__ double x[N];
__managed__ double y[N];
__managed__ double z[N];

int main() {
  for (int i = 0; i < N; ++i) {
    x[i] = (double)i;
    y[i] = 2.0;
  }

  product<<<(N + BLOCK_SIZE - 1) / BLOCK_SIZE, BLOCK_SIZE>>>(x, y, z, N);

  cudaDeviceSynchronize();

  for (int i = 0; i < N; ++i) {
    printf("%lf * %lf = %lf\n", x[i], y[i], z[i]);
  }
  return 0;
}

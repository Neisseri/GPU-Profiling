#include <cstdio>
#include <unistd.h>

__global__ void product(const double *x, const double *y, double *z, int n) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i < n) {
    z[i] = x[i] * y[i];
  }
}

constexpr int N = 128;
constexpr int BLOCK_SIZE = 32;

int main() {
  double *x = new double[N];
  double *y = new double[N];
  double *z = new double[N];

  for (int i = 0; i < N; ++i) {
    x[i] = (double)i;
    y[i] = 2.0;
  }

  double *d_x, *d_y, *d_z;
  cudaMalloc((void **)&d_x, N * sizeof(double));

  sleep(3);

  cudaMalloc((void **)&d_y, N * sizeof(double));

  sleep(3);

  cudaMalloc((void **)&d_z, N * sizeof(double));

  cudaMemcpy(d_x, x, N * sizeof(double), cudaMemcpyHostToDevice);
  cudaMemcpy(d_y, y, N * sizeof(double), cudaMemcpyHostToDevice);

  product<<<(N + BLOCK_SIZE - 1) / BLOCK_SIZE, BLOCK_SIZE>>>(d_x, d_y, d_z, N);

  cudaMemcpy(z, d_z, N * sizeof(double), cudaMemcpyDeviceToHost);

  sleep(3);

  cudaFree(d_z);

  sleep(3);

  cudaFree(d_y);
  
  sleep(3);
  
  cudaFree(d_x);

  for (int i = 0; i < N; ++i) {
    printf("%lf * %lf = %lf\n", x[i], y[i], z[i]);
  }

  delete[] z;
  delete[] y;
  delete[] x;
  return 0;
}

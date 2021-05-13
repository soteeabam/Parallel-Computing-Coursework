# Parallel-Computing-Coursework Makefile
To compile the OpenMP
gcc crackaes.c -lcrypto -fopenmp -o crackaes

To run the OpenMP
./crackaes


To compile OpenMPI
mpicc -o crackaesmpi crackaesmpi.c -lcrypto


To run the OpenMPI 
mpirun -np 2 crackaesmpi

#!/bin/bash

mkdir dir1
mkdir dir1/dir2
mkdir dir1/dir2/dir3
mkdir dir1/dir2/dir3/dir4
mkdir dir1/dir2/dir3/dir5
mkdir MCMC0683
mkdir MCMC0683/msd_dir1/msd_dir2
mkdir MCMC0683/msd_dir1/msd_dir2/~
mkdir MCMC0683/msd_dir1/msd_dir2/~/~tilde_dir
mkdir dir1/~
mkdir dir1/~/~

echo "hello" > dir1/dir2/file0

./isobusfs_create_test_file.sh dir1/dir2/file1k 1024
./isobusfs_create_test_file.sh dir1/dir2/file1m 1048576

# SPDX-License-Identifier: GPL-2.0

ccflags-y				+= -I$(src)

obj-$(CONFIG_NVME_CORE)			+= nvme-core.o
obj-$(CONFIG_BLK_DEV_NVME)		+= nvme.o
obj-$(CONFIG_NVME_FABRICS)		+= nvme-fabrics.o
obj-$(CONFIG_NVME_RDMA)			+= nvme-rdma.o
obj-$(CONFIG_NVME_FC)			+= nvme-fc.o
obj-$(CONFIG_NVME_TCP)			+= nvme-tcp.o
#obj-$(CONFIG_NVME_TREENVME)		+= treenvme.o
obj-$(CONFIG_BPF_TREENVME)		+= bpf-ddp.o

nvme-core-y				:= core.o
nvme-core-$(CONFIG_TRACING)		+= trace.o
nvme-core-$(CONFIG_NVME_MULTIPATH)	+= multipath.o
nvme-core-$(CONFIG_NVM)			+= lightnvm.o
nvme-core-$(CONFIG_FAULT_INJECTION_DEBUG_FS)	+= fault_inject.o
nvme-core-$(CONFIG_NVME_HWMON)		+= hwmon.o
#nvme-core-$(CONFIG_NVME_TREENVME)	+= treenvme.o
#nvme-core-$(CONFIG_BPF_TREENVME)	+= bpf-ddp.o

nvme-y					+= pci.o
#nvme-tree-$(CONFIG_NVME_TREENVME)	+= core.o pci.o treenvme.o
nvme-$(CONFIG_NVME_TREENVME)		+= treenvme.o

nvme-fabrics-y				+= fabrics.o

nvme-rdma-y				+= rdma.o

nvme-fc-y				+= fc.o

nvme-tcp-y				+= tcp.o

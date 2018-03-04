#include <ntddk.h>
#include "StructDefine.h"
#include "Common.h"
#include "ExitHandle.h"

BOOLEAN IsVtEnabled()
{
	ULONG uCr0, uCr4;
	MSR Msr;
	CPUID_VALUE CpuId;

	uCr0 = Asm_GetCr0();
	uCr4 = Asm_GetCr4();
	CpuId = Asm_GetCpuid(0x1);
	(*(PULONG64)&Msr) = Asm_Rdmsr(MSR_IA32_FEATURE_CONTROL);

	/*KdPrint(("CPUID:%x\n", uCpuId));
	KdPrint(("CR0:%x\n", uCr0));
	KdPrint(("CR4:%x\n", uCr4));
	KdPrint(("Msr-MSR_IA32_FEATURE_CONTROL-0x03a:%x-%x", HighMsr, LowMsr));*/

	if ((CpuId.u_Ecx & 0x20) == 0)					//�ж�cpuid�Ŀ�����Ϣ�е�VMXλ�Ƿ�Ϊ1
	{
		KdPrint(("���CPU��֧��VT��\n"));
		return FALSE;
	}

	if ((uCr0 & 0x1) == 0)							//�ж�cr0�е�PEλ�Ƿ�Ϊ1�����Ϊ1����������ڱ���ģʽ��
	{
		KdPrint(("��ǰCPU����ʵ��ַģʽ��VT�����ã�\n"));
		return FALSE;
	}

	if ((uCr0 & 0x80000000) == 0)					//�ж�cr0�е�PGλ�Ƿ�Ϊ1�����Ϊ1��������˷�ҳ�ڴ�ģʽ
	{
		KdPrint(("��ǰCPUû�п�����ҳ�ڴ���ƣ�VT�����ã�\n"));
		return FALSE;
	}

	if ((uCr0 & 0x20) == 0)							//�ж�cr0�е�NEλ�Ƿ�Ϊ1�����Ϊ1���������Э������ģʽ���������֣�intel�ĵ��в�û��Ҫ�ж���һλ�����ǽ��������жϣ������ȷ�ϣ���
	{
		KdPrint(("��ǰCPUû�п���Э��������ƣ�VT�����ã�\n"));
		return FALSE;
	}

	if (uCr4 & 0x2000)
	{
		KdPrint(("��ǰCPU������VT�����Ǳ���������ռ�ã���رպ��ٳ��ԣ�\n"));
		return FALSE;
	}

	if ((Msr.LowPart & 0x1) == 0)
	{
		KdPrint(("��ǰCPU��VTָ��δ��������\n"));
		return FALSE;
	}

	KdPrint(("��ǰ��CPU֧��VT!\n"));

	return TRUE;
}

NTSTATUS AllocateVMXRegion()
{
	PVOID pVMXONRegion;
	PVOID pVMCSRegion;
	PVOID pHostEsp;

	pVMXONRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmon');
	if (!pVMXONRegion)
	{
		KdPrint(("ERROR:����VMXON�ڴ�����ʧ��!\n"));
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMXONRegion, 0x1000);

	pVMCSRegion = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'vmcs');
	if (!pVMCSRegion)
	{
		KdPrint(("ERROR:����VMCS�ڴ�����ʧ��!\n", 0));
		ExFreePoolWithTag(pVMXONRegion, 'vmon');
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pVMCSRegion, 0x1000);

	pHostEsp = ExAllocatePoolWithTag(NonPagedPool, 0x2000, 'mini');
	if (!pHostEsp)
	{
		KdPrint(("ERROR:������������������ʧ��!\n", 0));
		ExFreePoolWithTag(pVMXONRegion, 'vmon');
		ExFreePoolWithTag(pVMCSRegion, 'mini');
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pHostEsp, 0x2000);

	/*KdPrint(("TIP:VMXON�ڴ������ַ :%x\n", pVMXONRegion));
	KdPrint(("TIP:VMCS�ڴ������ַ %x\n", pVMCSRegion));
	KdPrint(("TIP:���������������ַ %x\n", pHostEsp));*/

	g_VMXCPU.pVMXONRegion = pVMXONRegion;
	g_VMXCPU.pVMXONRegion_PA = MmGetPhysicalAddress(pVMXONRegion);
	g_VMXCPU.pVMCSRegion = pVMCSRegion;
	g_VMXCPU.pVMCSRegion_PA = MmGetPhysicalAddress(pVMCSRegion);
	g_VMXCPU.pHostEsp = pHostEsp;
	return STATUS_SUCCESS;
}

NTSTATUS SetupVMxRegion()
{
	VMX_BASIC_MSR Msr;
	CR4 u_Cr4;
	EFLAGS u_Eflags;

	(*(PULONG64)&Msr) = Asm_Rdmsr(MSR_IA32_VMX_BASIC);
	*((PULONG)g_VMXCPU.pVMXONRegion) = Msr.RevId;
	*((PULONG)g_VMXCPU.pVMCSRegion) = Msr.RevId;
	KdPrint(("Vmx�汾��Ϊ��%x\n", Msr.RevId));

	(*(PULONG)&u_Cr4) = Asm_GetCr4();
	u_Cr4.VMXE = 1;
	Asm_SetCr4(*(PULONG)&u_Cr4);					//����Cr4�Ĵ�����VMXEλΪ1

	//����vmxon
	Vmx_VmxOn(g_VMXCPU.pVMXONRegion_PA.LowPart, g_VMXCPU.pVMXONRegion_PA.HighPart);

	(*(PULONG)&u_Eflags) = Asm_GetEflags();
	if (u_Eflags.CF != 0 || u_Eflags.ZF != 0)
	{
		KdPrint(("ERROR:VMXONָ�����ʧ��!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	g_VMXCPU.bVTStartSuccess = TRUE;

	return STATUS_SUCCESS;
}

VOID SetupVMCS()
{
	ULONG GdtBase, IdtBase, uCPUBase;
	USHORT GdtLimit, IdtLimit;
	SEGMENT_SELECTOR SegmentSelector;
	EFLAGS u_Eflags;

	//ULONG u_CPUBase;
	//ULONG  u_ExceptionBitmap;

	//Vmclearһ��Vmcs�������ַ
	Vmx_VmClear(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);
	*((PULONG)&u_Eflags) = Asm_GetEflags();
	if (u_Eflags.CF != 0 || u_Eflags.ZF != 0)
	{
		KdPrint(("ERROR:VMCLEARָ�����ʧ��!\n"));
		return;
	}
	Vmx_VmPtrld(g_VMXCPU.pVMCSRegion_PA.LowPart, g_VMXCPU.pVMCSRegion_PA.HighPart);

	GdtBase = Asm_GetGdtBase();
	GdtLimit = Asm_GetGdtLimit();
	IdtBase = Asm_GetIdtBase();
	IdtLimit = Asm_GetIdtLimit();						//��ȡGDT���IDT�����Ϣ

	Vmx_VmWrite(GUEST_CR0, Asm_GetCr0());				//��ʼ���ͻ�����Cr0
	Vmx_VmWrite(GUEST_CR3, Asm_GetCr3());				//��ʼ���ͻ�����Cr3
	Vmx_VmWrite(GUEST_CR4, Asm_GetCr4());				//��ʼ���ͻ�����Cr4��ʵ���϶��Ǻ�������һ������ֵ
	Vmx_VmWrite(GUEST_DR7, 0x400);						//��ʼ���ͻ�����Dr7
	Vmx_VmWrite(GUEST_RFLAGS, Asm_GetEflags());			//��ʼ���ͻ�����Eflags�Ĵ���

	FillGuestSelectorData(GdtBase, ES, Asm_GetSegRegister(ES));
	FillGuestSelectorData(GdtBase, FS, Asm_GetSegRegister(FS));
	FillGuestSelectorData(GdtBase, DS, Asm_GetSegRegister(DS));
	FillGuestSelectorData(GdtBase, CS, Asm_GetSegRegister(CS));
	FillGuestSelectorData(GdtBase, SS, Asm_GetSegRegister(SS));
	FillGuestSelectorData(GdtBase, GS, Asm_GetSegRegister(GS));
	FillGuestSelectorData(GdtBase, TR, Asm_GetSegRegister(TR));
	FillGuestSelectorData(GdtBase, LDTR, Asm_GetSegRegister(LDTR));

	Vmx_VmWrite(GUEST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(GUEST_GDTR_LIMIT, GdtLimit);
	Vmx_VmWrite(GUEST_IDTR_BASE, IdtBase);
	Vmx_VmWrite(GUEST_IDTR_LIMIT, IdtLimit);

	Vmx_VmWrite(GUEST_IA32_DEBUGCTL, Asm_Rdmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	Vmx_VmWrite(GUEST_IA32_DEBUGCTL_HIGH, Asm_Rdmsr(MSR_IA32_DEBUGCTL) >> 32);

	Vmx_VmWrite(GUEST_SYSENTER_CS, Asm_Rdmsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_ESP, Asm_Rdmsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
	Vmx_VmWrite(GUEST_SYSENTER_EIP, Asm_Rdmsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF);			// KiFastCallEntry

	Vmx_VmWrite(GUEST_RSP, GuestEsp);
	Vmx_VmWrite(GUEST_RIP, GuestReturn);													// ָ��vmlaunch�ͻ�������ڵ� ���������ÿͻ�������ִ�м��������Ĵ���

	Vmx_VmWrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	Vmx_VmWrite(GUEST_ACTIVITY_STATE, 0);
	Vmx_VmWrite(VMCS_LINK_POINTER, 0xffffffff);
	Vmx_VmWrite(VMCS_LINK_POINTER_HIGH, 0xffffffff);

	//
	// 2.Host State Area
	//
	Vmx_VmWrite(HOST_CR0, Asm_GetCr0());
	Vmx_VmWrite(HOST_CR3, Asm_GetCr3());
	Vmx_VmWrite(HOST_CR4, Asm_GetCr4());

	Vmx_VmWrite(HOST_ES_SELECTOR, Asm_GetSegRegister(ES) & 0xFFF8);
	Vmx_VmWrite(HOST_CS_SELECTOR, Asm_GetSegRegister(CS) & 0xFFF8);
	Vmx_VmWrite(HOST_DS_SELECTOR, Asm_GetSegRegister(DS) & 0xFFF8);
	Vmx_VmWrite(HOST_FS_SELECTOR, Asm_GetSegRegister(FS) & 0xFFF8);
	Vmx_VmWrite(HOST_GS_SELECTOR, Asm_GetSegRegister(GS) & 0xFFF8);
	Vmx_VmWrite(HOST_SS_SELECTOR, Asm_GetSegRegister(SS) & 0xFFF8);
	Vmx_VmWrite(HOST_TR_SELECTOR, Asm_GetSegRegister(TR) & 0xFFF8);

	InitializeSegmentSelector(&SegmentSelector, Asm_GetSegRegister(FS), GdtBase);
	Vmx_VmWrite(HOST_FS_BASE, (ULONG)SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector, Asm_GetSegRegister(GS), GdtBase);
	Vmx_VmWrite(HOST_GS_BASE, (ULONG)SegmentSelector.base);
	InitializeSegmentSelector(&SegmentSelector, Asm_GetSegRegister(TR), GdtBase);
	Vmx_VmWrite(HOST_TR_BASE, (ULONG)SegmentSelector.base);

	Vmx_VmWrite(HOST_GDTR_BASE, GdtBase);
	Vmx_VmWrite(HOST_IDTR_BASE, IdtBase);

	Vmx_VmWrite(HOST_IA32_SYSENTER_CS, Asm_Rdmsr(MSR_IA32_SYSENTER_CS) & 0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_ESP, Asm_Rdmsr(MSR_IA32_SYSENTER_ESP) & 0xFFFFFFFF);
	Vmx_VmWrite(HOST_IA32_SYSENTER_EIP, Asm_Rdmsr(MSR_IA32_SYSENTER_EIP) & 0xFFFFFFFF); // KiFastCallEntry

	Vmx_VmWrite(HOST_RSP, ((ULONG)g_VMXCPU.pHostEsp) + 0x1FFF);//8KB 0x2000
	Vmx_VmWrite(HOST_RIP, (ULONG)Vmx_VMMEntryPoint);//���ﶨ�����ǵ�VMM����������

	// 3.��������п�����
	Vmx_VmWrite(PIN_BASED_VM_EXEC_CONTROL, VmxAdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));

	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	Vmx_VmWrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);
	Vmx_VmWrite(TSC_OFFSET, 0);
	Vmx_VmWrite(TSC_OFFSET_HIGH, 0);

	uCPUBase = VmxAdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS);
	//uCPUBase |= CPU_BASED_MOV_DR_EXITING; // ���ص��ԼĴ�������
	//uCPUBase |= CPU_BASED_USE_IO_BITMAPS; // ���ؼ��������Ϣ
	//uCPUBase |= CPU_BASED_ACTIVATE_MSR_BITMAP; // ����MSR����
	Vmx_VmWrite(CPU_BASED_VM_EXEC_CONTROL, uCPUBase);

	Vmx_VmWrite(CR3_TARGET_COUNT, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE0, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE1, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE2, 0);
	Vmx_VmWrite(CR3_TARGET_VALUE3, 0);

	// 4.VMEntry���п�����
	Vmx_VmWrite(VM_ENTRY_CONTROLS, VmxAdjustControls(0, MSR_IA32_VMX_ENTRY_CTLS));
	Vmx_VmWrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	// 5.VMExit���п�����
	Vmx_VmWrite(VM_EXIT_CONTROLS, VmxAdjustControls(VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	Vmx_VmWrite(VM_EXIT_MSR_LOAD_COUNT, 0);
	Vmx_VmWrite(VM_EXIT_MSR_STORE_COUNT, 0);

	Vmx_VmLaunch();

	g_VMXCPU.bVTStartSuccess = FALSE;

	KdPrint(("ERROR:VmLaunchָ�����ʧ��!ErrorCode is %x\n", Vmx_VmRead(VM_INSTRUCTION_ERROR)));
}

NTSTATUS StartVT()
{
	NTSTATUS status;

	//�����������VT
	if (!IsVtEnabled())
		return STATUS_NOT_SUPPORTED;

	//����ڴ����ʧ��
	status = AllocateVMXRegion();
	if (!NT_SUCCESS(status))
		return status;

	status = SetupVMxRegion();
	if (!NT_SUCCESS(status))
		return status;

	Vmx_SetupVmcs();

	if (g_VMXCPU.bVTStartSuccess == FALSE)
	{
		KdPrint(("����VTʧ�ܣ�\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("����VT�ɹ���\n"));
	return STATUS_SUCCESS;
}

NTSTATUS StopVT()
{
	CR4 u_Cr4;
	if (g_VMXCPU.bVTStartSuccess)
	{
		Vmx_VmCall('SVT');

		*((PULONG)&u_Cr4) = Asm_GetCr4();
		u_Cr4.VMXE = 0;
		Asm_SetCr4(*(PULONG)&u_Cr4);

		ExFreePoolWithTag(g_VMXCPU.pVMXONRegion, 'vmon');
		ExFreePoolWithTag(g_VMXCPU.pVMCSRegion, 'vmcs');
		ExFreePoolWithTag(g_VMXCPU.pHostEsp, 'mini');

		KdPrint(("�ɹ��ر�VT��\n"));
	}

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	StopVT();
	KdPrint(("Unload Success!\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	KdPrint(("Entry Driver!\n"));
	StartVT();
	DriverObject->DriverUnload = Unload;
	return STATUS_SUCCESS;
}
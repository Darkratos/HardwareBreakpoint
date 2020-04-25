#pragma once

// Define as estruturas ( ver manual intel )
struct Dr6 {
	/*0*/__int64 dr0_bp_state : 1;
	/*1*/__int64 dr1_bp_state : 1;
	/*2*/__int64 dr2_bp_state : 1;
	/*3*/__int64 dr3_bp_state : 1;

	/*4 - 12*/__int64 reserved1 : 8;

	/*13*/__int64 BD : 1;

	/*14*/__int64 BS : 1;

	/*15*/__int64 BT : 1;

	/*16*/__int64 RTM : 1;
};

struct Dr7 {
	/*0*/__int64 local_dr0_bp : 1;
	/*1*/__int64 global_dr0_bp : 1;

	/*2*/__int64 local_dr1_bp : 1;
	/*3*/__int64 global_dr1_bp : 1;

	/*4*/__int64 local_dr2_bp : 1;
	/*5*/__int64 global_dr2_bp : 1;

	/*6*/__int64 local_dr3_bp : 1;
	/*7*/__int64 global_dr3_bp : 1;

	/*8*/__int64 local_exact_bp : 1;
	/*9*/__int64 global_exact_bp : 1;

	/*10*/__int64 unk1 : 1;

	/*11*/__int64 restricted_transactional_memory : 1;

	/*12*/__int64 unk2 : 1;

	/*13*/__int64 general_detect_enable : 1;

	/*14 & 15*/__int64 unk3 : 2;

	/*16 & 17*/__int64 dr0_permissions : 2;
	/*18 & 19*/__int64 dr0_length : 2;

	/*20 & 21*/__int64 dr1_permissions : 2;
	/*22 & 23*/__int64 dr1_length : 2;

	/*24 & 25*/__int64 dr2_permissions : 2;
	/*26 & 27*/__int64 dr2_length : 2;

	/*28 & 29*/__int64 dr3_permissions : 2;
	/*30 & 31*/__int64 dr3_length : 2;
};

typedef struct _EFLAGS
{
	unsigned __int64 value;

	struct
	{
		unsigned __int32 cf : 1;
		unsigned __int32 reserved_0 : 1;
		unsigned __int32 pf : 1;
		unsigned __int32 reserved_1 : 1;
		unsigned __int32 af : 1;
		unsigned __int32 reserved_2 : 1;
		unsigned __int32 zf : 1;
		unsigned __int32 sf : 1;
		unsigned __int32 tf : 1;
		unsigned __int32 interrupt_flag : 1;
		unsigned __int32 df : 1;
		unsigned __int32 of : 1;
		unsigned __int32 iopl : 2;
		unsigned __int32 nt : 1;
		unsigned __int32 reserved_3 : 1;
		unsigned __int32 rf : 1;
		unsigned __int32 vm : 1;
		unsigned __int32 ac : 1;
		unsigned __int32 vif : 1;
		unsigned __int32 vip : 1;
		unsigned __int32 id : 1;
		unsigned __int32 reserved_4 : 10;
	}b;
} EFLAGS , * ERFLAGS;

// Breakpoint conditions
enum BP_COND
{
	BP_EXECUTE = 0,
	BP_WRITE = 1,
	BP_ACCESS = 3
};

// Class principal
class cHWBP
{
public:
	void set_dr0( uintptr_t address , int condition , int size );
	void set_dr1( uintptr_t address , int condition , int size );
	void set_dr2( uintptr_t address , int condition , int size );
	void set_dr3( uintptr_t address , int condition , int size );

	void set_dr0( uintptr_t address , int condition , int size , HANDLE thread );
	void set_dr1( uintptr_t address , int condition , int size , HANDLE thread );
	void set_dr2( uintptr_t address , int condition , int size , HANDLE thread );
	void set_dr3( uintptr_t address , int condition , int size , HANDLE thread );

	void clear( void );
	void HookLdrInitializeThunk( void );

	bool is_dr0_active = 0;
	bool is_dr1_active = 0;
	bool is_dr2_active = 0;
	bool is_dr3_active = 0;

	uintptr_t dr0_address = 0;
	uintptr_t dr1_address = 0;
	uintptr_t dr2_address = 0;
	uintptr_t dr3_address = 0;

	int dr0_condition = 0;
	int dr1_condition = 0;
	int dr2_condition = 0;
	int dr3_condition = 0;

	int dr0_size = 0;
	int dr1_size = 0;
	int dr2_size = 0;
	int dr3_size = 0;

private:
	std::vector<HANDLE> GetRunningThreads( );
	DWORD HookFunction( DWORD Function , DWORD YourFunction , bool ForceE8 = false );
};

// Define um objeto cHWBP global para ser usado tanto pelo user, quanto pelo hook na LdrInitializeThunk
cHWBP* hwbp = new cHWBP;
#include "pch.h"

// Define o tipo da função LdrInitializeThunk
typedef NTSTATUS( WINAPI* _LdrInitializeThunk )( DWORD Unknown1 , DWORD Unknown2 , DWORD Unknown3 );
_LdrInitializeThunk o_LdrInitializeThunk;

// Hook do LdrInitializeThunk, usado para aplicar o breakpoint em threads recém criadas ( créditos ao iPower )
NTSTATUS WINAPI LdrInitializeThunkHk( DWORD Unknown1 , DWORD Unknown2 , DWORD Unknown3 )
{
	// Pega a thread atual
	auto current_thread = GetCurrentThread( );

	// Se o breakpoint DrX estiver ativo, ativa ele na thread atual
	if ( hwbp->is_dr0_active )
		hwbp->set_dr0( hwbp->dr0_address , hwbp->dr0_condition , hwbp->dr0_size, current_thread );

	if ( hwbp->is_dr1_active )
		hwbp->set_dr1( hwbp->dr1_address , hwbp->dr1_condition , hwbp->dr1_size , current_thread );

	if ( hwbp->is_dr2_active )
		hwbp->set_dr2( hwbp->dr2_address , hwbp->dr2_condition , hwbp->dr2_size , current_thread );

	if ( hwbp->is_dr3_active )
		hwbp->set_dr3( hwbp->dr3_address , hwbp->dr3_condition , hwbp->dr3_size , current_thread );

	// Continua para a função original
	return o_LdrInitializeThunk( Unknown1 , Unknown2 , Unknown3 );
}

// Minha hook com calculo de size automático ( apenas para x86 )
DECLSPEC_NOINLINE DWORD cHWBP::HookFunction( DWORD Function , DWORD YourFunction , bool ForceE8 ) 
{
	// Se alguma das funções for nula, retorna 0
	if ( !Function || !YourFunction ) return 0;
	unsigned int length = 0;

	// Calcula o size da instrução ( lembrando que o hook tem que ter no minimo 5 bytes e não pode deixar instruções quebradas )
	while ( length < 5 ) {
		length += length_disasm( ( void* ) ( Function + length ) );
	}

	// Detecta automaticamente se você está hookando uma call
	if ( *( BYTE* ) Function == 0xE8 ) {
		// Se sim, apenas escreve o relative address e retorna o address original
		DWORD realaddress = *( DWORD* ) ( Function + 1 ) + ( DWORD ) Function + 5;
		*( DWORD* ) ( Function + 1 ) = YourFunction - Function - 5;
		return realaddress;
	}

	// Define as proteções e aloca espaço para a stub
	DWORD Old;
	DWORD NewLocation = ( DWORD ) VirtualAlloc( NULL , length + 5 , MEM_COMMIT , PAGE_EXECUTE_READWRITE );
	VirtualProtect( ( PVOID ) Function , length , PAGE_EXECUTE_READWRITE , &Old );
	VirtualProtect( ( PVOID ) NewLocation , length + 5 , PAGE_EXECUTE_READWRITE , 0 );

	// Se estiver hookando em um local que contenha um JMP, aqui ele trata da relocação do jmp
	if ( *( BYTE* ) Function == 0xE9 ) {
		DWORD realaddress = *( DWORD* ) ( Function + 1 ) + ( DWORD ) Function + 5;
		*( BYTE* ) ( NewLocation ) = 0xE9;
		*( DWORD* ) ( NewLocation + 1 ) = ( realaddress - NewLocation - 5 );
	}
	else {
		// Se não, apenas copia os bytes ( sim, falta checagens de instruções relativas, mas fiquei com preguiça :D )
		memcpy( ( void* ) NewLocation , ( void* ) Function , length );
	}

	// Escreve o jmp para a stub
	*( BYTE* ) ( NewLocation + length ) = 0xE9;
	*( DWORD* ) ( NewLocation + length + 1 ) = ( Function - NewLocation - 5 );

	// Se foi especificado para forçar E8 ( call ), escreve 0xE8, se não, escreve 0xE9 ( jmp )
	if ( ForceE8 )
		* ( BYTE* ) ( Function ) = 0xE8;
	else
		*( BYTE* ) ( Function ) = 0xE9;

	// Escreve o endereço relativo
	*( DWORD* ) ( Function + 1 ) = ( YourFunction - Function - 5 );

	// Retorna a stub
	return NewLocation;
}

DECLSPEC_NOINLINE std::vector<HANDLE> cHWBP::GetRunningThreads( ) 
{
	std::vector<HANDLE> retVec;

	int CurrentThreadID = GetCurrentThreadId( );

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Cria o snapshot das threads rodando
	hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD , 0 );

	// Se falhar, retorna o vector nulo
	if ( hThreadSnap == INVALID_HANDLE_VALUE )
		return retVec;

	// Preenche o dwSize ( necessario para o Thread32First )
	te32.dwSize = sizeof( THREADENTRY32 );

	// Pega informações sobre a thread atual e sai caso falhe
	if ( !Thread32First( hThreadSnap , &te32 ) )
	{
		CloseHandle( hThreadSnap );     // Limpa o objeto da snapshot
		return retVec;
	}

	// Agora ele itera sobre as threads que estão rodando usando Thread32Next
	do
	{
		// Verifica se de fato a thread é do processo atual ( não tenho certeza se é realmente necessario )
		if ( te32.th32OwnerProcessID == GetCurrentProcessId( ) )
		{
			// Pega apenas threads que não sejam a atual
			if ( te32.th32ThreadID != CurrentThreadID ) {
				// Pega um handle com permissão de acesso total na thread
				HANDLE curThread = OpenThread( THREAD_ALL_ACCESS , false , te32.th32ThreadID );

				// Se o handle for valido, coloca ele no vector
				if ( curThread != INVALID_HANDLE_VALUE )
					retVec.push_back( curThread );
			}
		}
	} while ( Thread32Next( hThreadSnap , &te32 ) );

	// Limpa o objeto da snapshot e retorna o vector
	CloseHandle( hThreadSnap );
	return retVec;
}

// Função para ativar o hook na LdrInitializeThunk
DECLSPEC_NOINLINE void cHWBP::HookLdrInitializeThunk( void )
{
	// Pega o address da LdrInitializeThunk
	auto dwLdrInitializeThunk = reinterpret_cast< uintptr_t > ( GetProcAddress( GetModuleHandle( "ntdll.dll" ) , "LdrInitializeThunk" ) );

	// Se conseguir um address, aplica o hook
	if ( dwLdrInitializeThunk ) {
		o_LdrInitializeThunk = reinterpret_cast< _LdrInitializeThunk > ( HookFunction( dwLdrInitializeThunk , reinterpret_cast< uintptr_t > ( LdrInitializeThunkHk ) ) );
	}
}

// Seta o breakpoint Dr0 em todas as threads
// Vou comentar apenas esse, os outros seguem o mesmo padrão
DECLSPEC_NOINLINE void cHWBP::set_dr0( uintptr_t address , int condition , int size )
{
	int m_index;
	CONTEXT cxt;

	// Seta os atributos na class para serem acessados pelo hook caso necessário
	is_dr0_active = true;
	dr0_address = address;
	dr0_condition = condition;
	dr0_size = size;

	// Calcula condição e size corretos ( olhar manual intel )
	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	// Itera sobre as threads
	for ( auto thisThread : GetRunningThreads( ) ) {
		// Suspende a thread para que não haja discrepância de EIP, registers, etc
		SuspendThread( thisThread );

		// Seta as ContextFlags para usar no GetThreadContext
		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

		// Se falhar no GetThreadContext, passa para a proxima thread
		if ( !GetThreadContext( thisThread , &cxt ) )
		{
			continue;
		}

		// Pega o Dr7 e eflags atual
		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );
		EFLAGS* eflags = reinterpret_cast< EFLAGS* > ( &cxt.EFlags );

		// Seta o breakpoint e suas características
		cxt.Dr0 = address;
		curDr7->dr0_permissions = condition;
		curDr7->dr0_length = size;
		curDr7->local_dr0_bp = true;

		// Seta o context com o breakpoint na thread
		SetThreadContext( thisThread , &cxt );
		
		// Continua a execução na thread
		ResumeThread( thisThread );
	}
}

DECLSPEC_NOINLINE void cHWBP::set_dr1( uintptr_t address , int condition , int size )
{
	int m_index;
	CONTEXT cxt;

	is_dr1_active = true;
	dr1_address = address;
	dr1_condition = condition;
	dr1_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	for ( auto thisThread : GetRunningThreads( ) ) {
		SuspendThread( thisThread );

		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if ( !GetThreadContext( thisThread , &cxt ) )
		{
			continue;
		}

		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

		
		

		cxt.Dr1 = address;
		curDr7->dr1_permissions = condition;
		curDr7->dr1_length = size;
		curDr7->local_dr1_bp = true;

		SetThreadContext( thisThread , &cxt );

		ResumeThread( thisThread );
	}
}

DECLSPEC_NOINLINE void cHWBP::set_dr2( uintptr_t address , int condition , int size )
{
	int m_index;
	CONTEXT cxt;

	is_dr2_active = true;
	dr2_address = address;
	dr2_condition = condition;
	dr2_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	for ( auto thisThread : GetRunningThreads( ) ) {
		SuspendThread( thisThread );

		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if ( !GetThreadContext( thisThread , &cxt ) )
		{
			continue;
		}

		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

		
		

		cxt.Dr2 = address;
		curDr7->dr2_permissions = condition;
		curDr7->dr2_length = size;
		curDr7->local_dr2_bp = true;

		SetThreadContext( thisThread , &cxt );

		ResumeThread( thisThread );
	}
}

DECLSPEC_NOINLINE void cHWBP::set_dr3( uintptr_t address , int condition , int size )
{
	int m_index;
	CONTEXT cxt;

	is_dr3_active = true;
	dr3_address = address;
	dr3_condition = condition;
	dr3_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	for ( auto thisThread : GetRunningThreads( ) ) {
		SuspendThread( thisThread );

		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		if ( !GetThreadContext( thisThread , &cxt ) )
		{
			continue;
		}

		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

		
		

		cxt.Dr3 = address;
		curDr7->dr3_permissions = condition;
		curDr7->dr3_length = size;
		curDr7->local_dr3_bp = true;

		SetThreadContext( thisThread , &cxt );

		ResumeThread( thisThread );
	}
}

// Aqui segue a mesma lógica, mas apenas para uma thread
DECLSPEC_NOINLINE void cHWBP::set_dr0( uintptr_t address , int condition , int size , HANDLE thread )
{
	int m_index;
	CONTEXT cxt;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( !GetThreadContext( thread , &cxt ) )
	{
		return;
	}

	Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );
	EFLAGS* eflags = reinterpret_cast< EFLAGS* > ( &cxt.EFlags );

	cxt.Dr0 = address;
	curDr7->dr0_permissions = condition;
	curDr7->dr0_length = size;
	curDr7->local_dr0_bp = true;

	curDr7->local_exact_bp = 1;
	eflags->b.tf = 1;

	SetThreadContext( thread , &cxt );
}

DECLSPEC_NOINLINE void cHWBP::set_dr1( uintptr_t address , int condition , int size , HANDLE thread )
{
	int m_index;
	CONTEXT cxt;

	is_dr1_active = true;
	dr1_address = address;
	dr1_condition = condition;
	dr1_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( !GetThreadContext( thread , &cxt ) )
	{
		return;
	}

	Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

	cxt.Dr1 = address;
	curDr7->dr1_permissions = condition;
	curDr7->dr1_length = size;
	curDr7->local_dr1_bp = true;

	SetThreadContext( thread , &cxt );
}

DECLSPEC_NOINLINE void cHWBP::set_dr2( uintptr_t address , int condition , int size , HANDLE thread )
{
	int m_index;
	CONTEXT cxt;

	is_dr2_active = true;
	dr2_address = address;
	dr2_condition = condition;
	dr2_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( !GetThreadContext( thread , &cxt ) )
	{
		return;
	}

	Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

	cxt.Dr2 = address;
	curDr7->dr2_permissions = condition;
	curDr7->dr2_length = size;
	curDr7->local_dr2_bp = true;

	SetThreadContext( thread , &cxt );
}

DECLSPEC_NOINLINE void cHWBP::set_dr3( uintptr_t address , int condition , int size , HANDLE thread )
{
	int m_index;
	CONTEXT cxt;

	is_dr3_active = true;
	dr3_address = address;
	dr3_condition = condition;
	dr3_size = size;

	condition = ( condition == 2 ) ? 3 : condition;
	size = ( size == 2 ) ? 3 : size;

	SuspendThread( thread );

	cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if ( !GetThreadContext( thread , &cxt ) )
	{
		return;
	}

	Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

	
	

	cxt.Dr3 = address;
	curDr7->dr3_permissions = condition;
	curDr7->dr3_length = size;
	curDr7->local_dr3_bp = true;

	SetThreadContext( thread , &cxt );

	ResumeThread( thread );
}

// Limpa todos os breakpoints
void cHWBP::clear( void )
{
	int m_index;
	CONTEXT cxt;

	// Limpa as flags da class
	is_dr0_active = false;
	is_dr1_active = false;
	is_dr2_active = false;
	is_dr3_active = false;

	dr0_address = 0;
	dr1_address = 0;
	dr2_address = 0;
	dr3_address = 0;

	dr0_condition = 0;
	dr1_condition = 0;
	dr2_condition = 0;
	dr3_condition = 0;

	dr0_size = 0;
	dr1_size = 0;
	dr2_size = 0;
	dr3_size = 0;

	// Itera por todas as threads
	for ( auto thisThread : GetRunningThreads( ) ) {
		// Suspende para evitar a discrepância
		SuspendThread( thisThread );

		// Seta a flag pro GetThreadContext
		cxt.ContextFlags = CONTEXT_DEBUG_REGISTERS;

		// Se falhar, vai pra próxima thread
		if ( !GetThreadContext( thisThread , &cxt ) )
			continue;

		// Pega o Dr7 atual
		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &cxt.Dr7 );

		// Limpa os breakpoints
		cxt.Dr0 = 0;
		curDr7->dr0_permissions = 0;
		curDr7->dr0_length = 0;
		curDr7->local_dr0_bp = false;
		curDr7->global_dr0_bp = false;

		cxt.Dr1 = 0;
		curDr7->dr1_permissions = 0;
		curDr7->dr1_length = 0;
		curDr7->local_dr1_bp = false;
		curDr7->global_dr1_bp = false;

		cxt.Dr2 = 0;
		curDr7->dr2_permissions = 0;
		curDr7->dr2_length = 0;
		curDr7->local_dr2_bp = false;
		curDr7->global_dr2_bp = false;

		cxt.Dr3 = 0;
		curDr7->dr3_permissions = 0;
		curDr7->dr3_length = 0;
		curDr7->local_dr3_bp = false;
		curDr7->global_dr3_bp = false;

		// Aplica o novo context sem os breakpoints
		SetThreadContext( thisThread , &cxt );

		// Continua a execução na thread
		ResumeThread( thisThread );
	}
}
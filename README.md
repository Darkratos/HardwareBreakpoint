# HardwareBreakpoint

Created this class a while ago to make it easy to reverse engineer games.  
This code was meant for x86 apps on Windows with intel processor.  
The code is documented in portuguese ( PT-BR ).  

It only needs an exception handler to get the breakpoint hits.  
Example:  

```cpp
long __stdcall exception_handler( _EXCEPTION_POINTERS* ex )
{
  // Check if the exception was due a SINGLE_STEP
	if ( ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {
  
    // Get the Dr6 ( to check the breakpoint states )
		Dr6* curDr6 = reinterpret_cast< Dr6* > ( &ex->ContextRecord->Dr6 );
    // Get the Dr7 ( to check the breakpoint condition )
		Dr7* curDr7 = reinterpret_cast< Dr7* > ( &ex->ContextRecord->Dr7 );

		// Checks if it was trully a hardware breakpoint that caused the exception
		if ( !curDr6->dr0_bp_state && !curDr6->dr1_bp_state && !curDr6->dr2_bp_state && !curDr6->dr3_bp_state )
			return EXCEPTION_CONTINUE_EXECUTION;
      
		int hit_num = 0;
		bool execute_bp = true;

    // Checks each of the states to get which breakpoint hit
		if ( curDr6->dr0_bp_state ) {
      // Zeroes out the state
			curDr6->dr0_bp_state = 0;

      // Checks if it was an execution breakpoint
			if ( curDr7->dr0_permissions == 0 )
        // If it was, set the Resume-Flag to avoid looping
				ex->ContextRecord->EFlags |= ( 1 << 16 );
			else
				execute_bp = false;
		}
		else if ( curDr6->dr1_bp_state ) {
			curDr6->dr1_bp_state = 0;
			hit_num = 1;

			if ( curDr7->dr1_permissions == 0 )
				ex->ContextRecord->EFlags |= ( 1 << 16 );
			else
				execute_bp = false;
		}
		else if ( curDr6->dr2_bp_state ) {
			curDr6->dr2_bp_state = 0;
			hit_num = 2;

			if ( curDr7->dr2_permissions == 0 )
				ex->ContextRecord->EFlags |= ( 1 << 16 );
			else
				execute_bp = false;
		}
		else if ( curDr6->dr3_bp_state ) {
			curDr6->dr3_bp_state = 0;
			hit_num = 3;

			if ( curDr7->dr3_permissions == 0 )
				ex->ContextRecord->EFlags |= ( 1 << 16 );
			else
				execute_bp = false;
		}
    
    // Here you can print the address that generated the exception and do whatever you want
		uintptr_t addr = ex->ContextRecord->Eip;

    // Returns to normal program execution
		return EXCEPTION_CONTINUE_EXECUTION;
	}

  // The exception wasn't caused by a breakpoint, transfer to the next handler or a try/catch block
	return EXCEPTION_CONTINUE_SEARCH;
}```

To set the exception handler, use:  

```cpp
AddVectoredExceptionHandler( 1 , exception_handler );
SetUnhandledExceptionFilter( exception_handler );
```

And to set a breakpoint:  

```cpp
// Remember to enable the LdrInitializeThunk to make sure you get all the threads
hwbp->HookLdrInitializeThunk( );

// Set the breakpoint at the address 0xDEADBEEF
// The size doesn't matter for an execute breakpoint, but use 0 ( BYTE ), 1 ( WORD ) or 2 ( DWORD ) for WRITE/ACCESS
hwbp->set_dr0( 0xDEADBEEF, BP_EXECUTE, 1 );
```

public NtDCompositionProcessChannelBatchBuffer
public NtDCompositionCreateChannel
.code




NtDCompositionProcessChannelBatchBuffer proc
    mov     r10, rcx
    mov     eax, 1137h
    syscall
    ret
NtDCompositionProcessChannelBatchBuffer endp


NtDCompositionCreateChannel proc
    mov     r10, rcx
    mov     eax, 1124h
    syscall
    ret
NtDCompositionCreateChannel endp



end
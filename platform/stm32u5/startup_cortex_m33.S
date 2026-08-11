    .syntax unified
    .cpu cortex-m33
    .thumb

    .section .isr_vector, "a", %progbits
    .global g_pfnVectors
    .type g_pfnVectors, %object
g_pfnVectors:
    .word _estack
    .word Reset_Handler
    .size g_pfnVectors, . - g_pfnVectors

    .section .text.Reset_Handler, "ax", %progbits
    .global Reset_Handler
    .type Reset_Handler, %function
Reset_Handler:
    bl rampart_platform_reset_entry
1:
    b 1b
    .size Reset_Handler, . - Reset_Handler


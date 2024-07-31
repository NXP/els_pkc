////////////////////////////////////////////////////////////////////////////////
//
// NXP, Test Chip Cortex-M0, 
// Mario Meza
// 2014
////////////////////////////////////////////////////////////////////////////////

//map the peripherals in the memory space
#define APB_BASE		0x40000000
#define TEST_APB_BASE		0x40010000
#define EXP_1_APB_BASE		0x40020000
#define EXP_2_APB_BASE		0x40030000

#define LPUART_SYSTEM_CTRL  (*(volatile uint32_t  *)0x40011024)

#define REF_MULT_AES_BASE      (EXP_2_APB_BASE +0x5000) //FOR REFERENCE MODULE 5
#define REF_MULT_AES           ((REF_MULT_AES_Type *) REF_MULT_AES_BASE)


#define CAMOUFLAGE_STD_BASE     (EXP_2_APB_BASE +0x2000)
#define CAMOUFLAGE_STD          ((CAMOUFLAGE_Type *) (CAMOUFLAGE_STD_BASE + 0x40))
#define CAMOUFLAGE_DNW_BASE     (EXP_2_APB_BASE +0x3000)
#define CAMOUFLAGE_DNW          ((CAMOUFLAGE_Type *) (CAMOUFLAGE_DNW_BASE + 0x40))

#define CPU_ID (*(volatile uint32_t  *)(0xE000ED00))			

#define GLIKEY0_BASE    0x40028000
#define GLIKEY1_BASE    0x40029000

//dcv2 base address
#define DCV2_BASE       0x40027000


//SFR
#define _SFR_BASE_ 0x40010000
#define _SFR_BASE_SYS_CTRL_ 0x40011000
#define SFR_DECL(sfr_type,sfr_offset) (*(volatile unsigned sfr_type  *)(_SFR_BASE_+sfr_offset))
#define GEN_REG_IN_1 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x50))
#define GEN_REG_IN_2 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x54))
#define GEN_REG_IN_3 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x58))
#define GEN_REG_IN_4 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x5C))
#define GEN_REG_IN_5 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x60))
#define GEN_REG_IN_6 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x64))
#define GEN_REG_IN_7 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x68))
#define GEN_REG_IN_8 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x6C))
#define GEN_REG_IN_9 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x70))
#define GEN_REG_IN_10 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x74))
#define GEN_REG_IN_11 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x78))
#define GEN_REG_IN_12 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x7C))

#define GEN_REG_OUT_1 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x80))
#define GEN_REG_OUT_2 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x84))
#define GEN_REG_OUT_3 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x88))
#define GEN_REG_OUT_4 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x8C))
#define GEN_REG_OUT_5 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x90))
#define GEN_REG_OUT_6 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x94))
#define GEN_REG_OUT_7 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x98))
#define GEN_REG_OUT_8 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0x9C))
#define GEN_REG_OUT_9 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0xA0))
#define GEN_REG_OUT_10 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0xA4))
#define GEN_REG_OUT_11 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0xA8))
#define GEN_REG_OUT_12 (*(volatile uint32_t  *)(_SFR_BASE_SYS_CTRL_ + 0xAC))


#define _SFR_BASE_PERFORMANCE_COUNTER_ 0x40012000
#define PERF_COUNT_RESETN (*(volatile uint8_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x00))
#define PERF_COUNT_RUN (*(volatile uint8_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x01))
#define PERF_COUNT_OVERFLOW (*(volatile uint8_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x02))
#define PERF_COUNT_FREQ (*(volatile uint32_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x04))
#define PERF_COUNT_CLK_COUNTER (*(volatile uint32_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x08))
#define PERF_COUNT_TIME (*(volatile uint32_t  *)(_SFR_BASE_PERFORMANCE_COUNTER_ + 0x0C))
	
#define SEL_CLK (*(volatile unsigned char  *)(0x40011000))
#define ARM_CLK_DIV (*(volatile unsigned char  *)(0x40011001))
#define EXP_APB_CTRL (*(volatile unsigned char  *)(0x40011002))
#define SECONDARY_CLK_DIV (*(volatile unsigned char  *)(0x40011003))
#define EXP_1_APB_MOD_ENABLE (*(volatile unsigned short  *)(0x40011004))
#define EXP_2_APB_MOD_ENABLE (*(volatile unsigned short  *)(0x40011006))
#define EXP_1_APB_MOD_POWER (*(volatile unsigned short  *)(0x4001101C))
#define EXP_2_APB_MOD_POWER (*(volatile unsigned short  *)(0x4001101E))
// EXP 1 modules
#define FAME3_ENABLE (1<<0) //0 is the slot in the apb experimental bus
#define SECOND_TRNG_ENABLE (1<<1) //1 is the slot in the apb experimental bus
#define CSS_ENABLE (1<<2) //2 is the slot in the apb experimental bus
#define PUF_ENABLE (1<<3) //3 is the slot in the apb experimental bus
#define PUF_BEH_ENABLE (1<<4) //4 is the slot in the apb experimental bus
#define SM3_ENABLE (1<<6) //6 is the slot in the apb experimental bus
#define SGI_ENABLE (1<<6) //6 is the slot in the apb experimental bus
#define CHINA_SGI_ENABLE (1<<8) //8 is the slot in the apb experimental bus
#define AJAX_SGI_ENABLE (1<<9) //9 is the slot in the apb experimental bus
#define GTRACE_ENABLE (1<<10) //10 is the slot in the apb experimental bus
#define CSS_EXT_SFR_ENABLE_1 (1<<5) //5 is the slot in the apb experimental bus
#define CSS_EXT_SFR_ENABLE_2 (1<<11) //11 is the slot in the apb experimental bus // TODO Mario Meza: remove temp workaround
#define GLIKEY_1_ENABLE (1<<8) //8 is the slot in the apb experimental bus
#define GLIKEY_2_ENABLE (1<<9) //9 is the slot in the apb experimental bus

// SECURE_IP_ROM             module  3 
// SECURE_IP_COMB            module  4
// SECURE_IP_COMB_DIG_SENSOR modules 5/6
#define EXP_SECURE_IP_ROM_ENABLE             (1<<3)  // 3 is the slot in the apb experimental bus 
#define EXP_SECURE_IP_COMB_ENABLE            (1<<4)
#define EXP_SECURE_IP_COMB_DIG_SENSOR_ENABLE (3<<5)  // Slots 5 and 6 enabled

// EXP 2 modules
//#define PUF_1_ENABLE (1<<0) //0 is the slot in the apb experimental bus
//#define PUF_2_ENABLE (1<<1) //1 is the slot in the apb experimental bus
//#define PUF_3_ENABLE (1<<2) //2 is the slot in the apb experimental bus
#define CAMOUFLAGE_STD_ENABLE (1<<4) //4 is the slot in the apb experimental bus
#define CAMOUFLAGE_DNW_ENABLE (1<<5) //5 is the slot in the apb experimental bus

//FOR REFERENCE MODULE
#define EXP_REF_MULT_AES_ENABLE (1<<5) //5 is the slot in the apb experimental bus

#define GDET_1_ENABLE (1<<6) //6 is the slot in the apb experimental bus
#define GDET_2_ENABLE (1<<7) //7 is the slot in the apb experimental bus
#define GDET_3_ENABLE (1<<9) //9 is the slot in the apb experimental bus
#define GDET_4_ENABLE (1<<10) //10(0xA) is the slot in the apb experimental bus
#define GDET_5_ENABLE (1<<13) //10(0xD) is the slot in the apb experimental bus
#define GDET_6_ENABLE (1<<14) //10(0xE) is the slot in the apb experimental bus


// Added for quantum
#define CSS_HW_DRV_OFFSET_60  *(volatile uint32_t*) 0x40025060 // <= {reg_css_hw_drv_data[31:0]}
#define CSS_HW_DRV_OFFSET_64  *(volatile uint32_t*) 0x40025064 // <= {reg_css_hw_drv_data[63:32]}
#define CSS_HW_DRV_OFFSET_68  *(volatile uint32_t*) 0x40025068 // <= {reg_css_hw_drv_data[95:64]}
#define CSS_HW_DRV_OFFSET_6C  *(volatile uint32_t*) 0x4002506c // <= {reg_css_hw_drv_data[127:96]}

// Cosim registers addresses definition for the writable entropy feature
#define CSS_ENTROPY_ENA_54     *(volatile uint32_t*) 0x40025054 // <= {8'h00,8'h00,8'h00,{7'b0000000,reg_css_entropy_ena}}
#define CSS_ENTROPY_OFFSET_70  *(volatile uint32_t*) 0x40025070 // <= {reg_css_entropy_data[31:0]}
#define CSS_ENTROPY_OFFSET_74  *(volatile uint32_t*) 0x40025074 // <= {reg_css_entropy_data[63:32]}
#define CSS_ENTROPY_OFFSET_78  *(volatile uint32_t*) 0x40025078 // <= {reg_css_entropy_data[95:64]}
#define CSS_ENTROPY_OFFSET_7C  *(volatile uint32_t*) 0x4002507C // <= {reg_css_entropy_data[127:96]}
#define CSS_ENTROPY_OFFSET_80  *(volatile uint32_t*) 0x40025080 // <= {reg_css_entropy_data[159:128]}
#define CSS_ENTROPY_OFFSET_84  *(volatile uint32_t*) 0x40025084 // <= {reg_css_entropy_data[191:160]}
#define CSS_ENTROPY_OFFSET_88  *(volatile uint32_t*) 0x40025088 // <= {reg_css_entropy_data[223:192]}
#define CSS_ENTROPY_OFFSET_8C  *(volatile uint32_t*) 0x4002508C // <= {reg_css_entropy_data[255:224]}

///////////////////////////////////////////////////////////////////////////////////////////

#define LPUART_SYSTEM_CTRL  (*(volatile uint32_t  *)0x40011024)

#define _LPUART_BASE_ 0x40013000
#define LPUART_GLOBAL (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x08))
#define LPUART_BAUD (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x10))
#define LPUART_STATUS (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x14))
#define LPUART_CTRL (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x18))
#define LPUART_DATA (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x1C))

#define LPUART_TXRXSTATUS_MASK         0x01C00000
#define LPUART_TXRXRDY_MASK            0x00C00000
#define LPUART_TXEMPTY_MASK            0x00800000
#define LPUART_TXCOMPLETE_MASK         0x00400000

#define LPUART_RXFULL_MASK             0X00200000

#define LPUART_TXRXENABLE_MASK         0x000C0000
#define LPUART_TXRXENABLE_NEGMASK      0xFFF3FFFF
#define LPUART_BAUDRATE_NEGMASK        0xE0FFE000

#define LPUART_ERR_MASK                0x000B0000

#define EXP_APB_PRNG_ENABLE (1<<11)

// GTRACE masks
#define COSIM_EXP_1_APB_MOD_GTRACE_MASK          (1<<10)

// dcv2 masks
#define COSIM_EXP_1_APB_MOD_POWER_DCV2_MASK   (1<<7) 
#define COSIM_EXP_1_APB_MOD_POWER_CSS_MASK    (1<<2) 
#define COSIM_EXP_1_APB_MOD_DCV2_MASK         (1<<7)	
#define COSIM_EXP_1_APB_MOD_CSS_MASK          (1<<2)
#define COSIM_CSS_EXT_SFR_ENABLE_1_MASK		  (1<<5)	  
#define COSIM_CSS_EXT_SFR_ENABLE_2_MASK		  (1<<11)

// dcv2 ctrl : run ,reset and wrom_sel registers
#define DCV2_RUN                      (*(volatile uint8_t*)0x40027000)
#define DCV2_RESET                    (*(volatile uint8_t*)0x40027002)
#define DCV2_WROM_SEL                 (*(volatile uint8_t*)0x40027003)

// dcv2 breakpoints interrupt enable
#define  DCV2_INTERRUPT_ENABLE        (*(volatile uint8_t*)0x40027006)


//LPUART
///////////////////////////////////////////////////////////////////////////////////////////
#define _LPUART_BASE_ 0x40013000
#define LPUART_GLOBAL (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x08))
#define LPUART_BAUD (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x10))
#define LPUART_STATUS (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x14))
#define LPUART_CTRL (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x18))
#define LPUART_DATA (*(volatile uint32_t  *)(_LPUART_BASE_ + 0x1C))

#define LPUART_TXRXSTATUS_MASK         0x01C00000
#define LPUART_TXRXRDY_MASK            0x00C00000
#define LPUART_TXEMPTY_MASK            0x00800000
#define LPUART_TXCOMPLETE_MASK         0x00400000

#define LPUART_RXFULL_MASK             0X00200000

#define LPUART_TXRXENABLE_MASK         0x000C0000
#define LPUART_TXRXENABLE_NEGMASK      0xFFF3FFFF
#define LPUART_BAUDRATE_NEGMASK        0xE0FFE000

#define LPUART_ERR_MASK                0x000B0000


//
#define PRNG_CTRL (*(volatile uint32_t  *)(0x4003B000))
#define PRNG_SEED (*(volatile uint32_t  *)(0x4003B004))
#define PRNG_RDATA (*(volatile uint32_t  *)(0x4003B008))



--------------------------------------------------------------------------
-- |
-- Module      :  Text.Disassembler.X86Disassembler
-- Copyright   :  (c) Martin Grabmueller and Dirk Kleeblatt
-- License     :  BSD3
-- 
-- Maintainer  :  martin@grabmueller.de,klee@cs.tu-berlin.de
-- Stability   :  provisional
-- Portability :  portable
--
-- Disassembler for x86 machine code.
--
-- This is a disassembler for object code for the x86 architecture.
-- It provides functions for disassembling byte arrays, byte lists and
-- memory blocks containing raw binary code.
-- 
-- Features:
--
-- - Disassembles memory blocks, lists or arrays of bytes into lists of
--   instructions.
--
-- - Abstract instructions provide as much information as possible about
--   opcodes, addressing modes or operand sizes, allowing for detailed
--   output.
--
-- - Provides functions for displaying instructions in Intel or AT&T
--   style (like the GNU tools)
--
-- Differences to GNU tools, like gdb or objdump:
--
-- - Displacements are shown in decimal, with sign if negative.
--
-- Missing: 
--
-- - LOCK and repeat prefixes are recognized, but not contained in the
--   opcodes of instructions.
--
-- - Support for 16-bit addressing modes.  Could be added when needed.
--
-- - Complete disassembly of all 64-bit instructions.  I have tried to
--   disassemble them properly but have been limited to the information
--   in the docs, because I have no 64-bit machine to test on.  This will
--   probably change when I get GNU as to produce 64-bit object files.
--
-- - Not all MMX and SSE/SSE2/SSE3 instructions are decoded yet.  This is
--   just a matter of missing time.
--
-- - segment override prefixes are decoded, but not appended to memory
--   references
--
-- On the implementation:
--
-- This disassembler uses the Parsec parser combinators, working on byte
-- lists.  This proved to be very convenient, as the combinators keep
-- track of the current position, etc.
--------------------------------------------------------------------------

module Text.Disassembler.X86Disassembler(
  -- * Types
  Opcode,
  Operand(..),
  InstrOperandSize(..),
  Instruction(..),
  ShowStyle(..),
  Config(..),
  -- * Functions
  disassembleBlock,
  disassembleList,
  disassembleArray,
  disassembleFile,
  disassembleBlockWithConfig,
  disassembleListWithConfig,
  disassembleArrayWithConfig,
  disassembleFileWithConfig,
  showIntel,
  showAtt,
  defaultConfig
  ) where

import Text.ParserCombinators.Parsec
import Control.Monad.State
import System.IO
import Data.List
import Data.Char
import Data.Array.IArray
import Numeric
import Foreign

-- | All opcodes are represented by this enumeration type.

data Opcode = InvalidOpcode
	    | AAA
	    | AAD
	    | AAM
	    | AAS
	    | ADC
	    | ADD
	    | ADDPD
	    | ADDPS
	    | ADDSD
	    | ADDSS
	    | ADDSUBPD
	    | ADDUBPS
	    | AND
	    | ANDNPD
	    | ANDNPS
	    | ANDPD
	    | ANDPS
	    | ARPL
	    | BOUND
	    | BSF
	    | BSR
	    | BT
	    | BTC
	    | BTR
	    | BTS
	    | CALL
	    | CALLF
	    | CBW
	    | CDQ
	    | CDQE
	    | CLC
	    | CLD
	    | CLFLUSH
	    | CLI
	    | CLTS
	    | CMC
	    | CMOVA
	    | CMOVB
	    | CMOVBE
	    | CMOVE
	    | CMOVG
	    | CMOVGE
	    | CMOVL
	    | CMOVLE
	    | CMOVNB
	    | CMOVNE
	    | CMOVNO
	    | CMOVNP
	    | CMOVNS
	    | CMOVO
	    | CMOVP
	    | CMOVS
	    | CMP
	    | CMPS
	    | CMPXCHG
	    | CMPXCHG16B
	    | CMPXCHG8B
	    | COMISD
	    | COMISS
	    | CPUID
	    | CWD
	    | CWDE
	    | DAA
	    | DAS
	    | DEC
	    | DIV
	    | DIVPD
	    | DIVPS
	    | DIVSD
	    | DIVSS
	    | EMMS
	    | ENTER
	    | FABS
	    | FADD
	    | FADDP
	    | FBLD
	    | FBSTP
	    | FCHS
	    | FCLEX
	    | FCMOVB
	    | FCMOVBE
	    | FCMOVE
	    | FCMOVNB
	    | FCMOVNBE
	    | FCMOVNE
	    | FCMOVNU
	    | FCMOVU
	    | FCOM
	    | FCOMI
	    | FCOMIP
	    | FCOMP
	    | FCOMPP
	    | FDIV
	    | FDIVP
	    | FDIVR
	    | FDIVRP
	    | FFREE
	    | FIADD
	    | FICOM
	    | FICOMP
	    | FIDIV
	    | FIDIVR
	    | FILD
	    | FIMUL
	    | FINIT
	    | FIST
	    | FISTP
	    | FISTPP
	    | FISTTP
	    | FISUB
	    | FISUBR
	    | FLD
	    | FLD1
	    | FLDCW
	    | FLDENV
	    | FLDL2E
	    | FLDL2T
	    | FLDLG2
	    | FLDLN2
	    | FLDPI
	    | FLDZ
	    | FMUL
	    | FMULP
	    | FNOP
	    | FRSTOR
	    | FSAVE
	    | FST
	    | FSTCW
	    | FSTENV
	    | FSTP
	    | FSTSW
	    | FSUB
	    | FSUBP
	    | FSUBR
	    | FSUBRP
	    | FTST
	    | FUCOM
	    | FUCOMI
	    | FUCOMIP
	    | FUCOMP
	    | FUCOMPP
	    | FXAM
	    | FXCH
	    | FXRSTOR
	    | FXSAVE
	    | HADDPD
	    | HADDPS
	    | HLT
	    | HSUBPD
	    | HSUBPS
	    | IDIV
	    | IMUL
	    | BSWAP
	    | IN
	    | INC
	    | INS
	    | INT
	    | INT3
	    | INTO
	    | INVD
	    | INVLPG
	    | IRET
	    | JA
	    | JB
	    | JBE
	    | JCXZ
	    | JE
	    | JG
	    | JGE
	    | JL
	    | JLE
	    | JMP
	    | JMPF
	    | JMPN
	    | JNB
	    | JNE
	    | JNO
	    | JNP
	    | JNS
	    | JO
	    | JP
	    | JS
	    | LAHF
	    | LAR
	    | LDDQU
	    | LDMXCSR
	    | LDS
	    | LEA
	    | LEAVE
	    | LES
	    | LFENCE
	    | LFS
	    | LGDT
	    | LGS
	    | LIDT
	    | LLDT
	    | LMSW
	    | LODS
	    | LOOP
	    | LOOPE
	    | LOOPNE
	    | LSL
	    | LSS
	    | LTR
	    | MASKMOVQ
	    | MAXPD
	    | MAXPS
	    | MAXSD
	    | MAXSS
	    | MFENCE
	    | MINPD
	    | MINPS
	    | MINSD
	    | MINSS
	    | MONITOR
	    | MOV 
	    | MOVAPD
	    | MOVAPS
	    | MOVDDUP
	    | MOVHPD
	    | MOVHPS
	    | MOVLHPS
	    | MOVLPD
	    | MOVLPS
	    | MOVLSDUP
	    | MOVMSKPD
	    | MOVMSKPS
	    | MOVNTDQ
	    | MOVNTPD
	    | MOVNTPS
	    | MOVNTQ
	    | MOVQ
	    | MOVS
	    | MOVSD
	    | MOVSLDUP
	    | MOVSS
	    | MOVSXB
	    | MOVSXD
	    | MOVSXW
	    | MOVUPD
	    | MOVUPS
	    | MOVZXB
	    | MOVZXW
	    | MUL
	    | MULPD
	    | MULPS
	    | MULSD
	    | MULSS
	    | MWAIT
	    | NEG
	    | NOP
	    | NOT
	    | OR
	    | ORPD
	    | ORPS
	    | OUT
	    | OUTS
	    | PADDB
	    | PADDD
	    | PADDQ
	    | PADDSB
	    | PADDSW
	    | PADDUSB
	    | PADDUSW
	    | PADDW
	    | PAND
	    | PANDN
	    | PAUSE
	    | PAVGB
	    | PAVGW
	    | PMADDWD
	    | PMAXSW
	    | PMAXUB
	    | PMINSW
	    | PMINUB
	    | PMOVMSKB
	    | PMULHUW
	    | PMULHW
	    | PMULLW
	    | PMULUDQ
	    | POP
	    | POPA
	    | POPAD
	    | POPF
	    | POPFD
	    | POPFQ
	    | POR
	    | PREFETCHNTA
	    | PREFETCHT0
	    | PREFETCHT1
	    | PREFETCHT2
	    | PSADBW
	    | PSLLD
	    | PSLLDQ
	    | PSLLQ
	    | PSLLW
	    | PSRAD
	    | PSRAW
	    | PSRLD
	    | PSRLDQ
	    | PSRLQ
	    | PSRLW
	    | PSUBB
	    | PSUBD
	    | PSUBQ
	    | PSUBSB
	    | PSUBSQ
	    | PSUBUSB
	    | PSUBUSW
	    | PSUBW
	    | PUSH
	    | PUSHA
	    | PUSHAD
	    | PUSHF
	    | PUSHFD
	    | PUSHFQ
	    | PXOR
	    | RCL
	    | RCPPS
	    | RCPSS
	    | RCR
	    | RDMSR
	    | RDPMC
	    | RDTSC
	    | RET
	    | RETF
	    | ROL
	    | ROR
	    | RSM
	    | RSQRTPS
	    | RSQRTSS
	    | SAHF
	    | SAR
	    | SBB
	    | SCAS
	    | SETA
	    | SETB
	    | SETBE
	    | SETE
	    | SETG
	    | SETGE
	    | SETL
	    | SETLE
	    | SETNB
	    | SETNE
	    | SETNO
	    | SETNP
	    | SETNS
	    | SETO
	    | SETP
	    | SETS
	    | SFENCE
	    | SGDT
	    | SHL
	    | SHLD
	    | SHR
	    | SHRD
	    | SIDT
	    | SLDT
	    | SMSW
	    | SQRTPD
	    | SQRTPS
	    | SQRTSD
	    | SQRTSS
	    | STC
	    | STD
	    | STI
	    | STMXCSR
	    | STOS
	    | STR
	    | SUB
	    | SUBPD
	    | SUBPS
	    | SUBSD
	    | SUBSS
	    | SWAPGS
	    | SYSCALL
	    | SYSENTER
	    | SYSEXIT
	    | TEST
	    | UCOMISD
	    | UCOMISS
	    | UD2
	    | UNPCKHPD
	    | UNPCKHPS
	    | UNPCKLPD
	    | UNPCKLPS
	    | VERR
	    | VERW
	    | VMCALL
	    | VMCLEAR
	    | VMLAUNCH
	    | VMPTRLD
	    | VMPTRST
	    | VMREAD
	    | VMRESUME
	    | VMWRITE
	    | VMXOFF
	    | VMXON
	    | WAIT
	    | WBINVD
	    | WRMSR
	    | XADD
	    | XCHG
	    | XLAT
	    | XOR
	    | XORPD
	    | XORPS
  deriving (Show, Eq)

-- Display an opcode in lower case.

showOp :: Opcode -> String
showOp = (map toLower) . show

-- | All operands are in one of the following locations:
--
-- - Constants in the instruction stream
--
-- - Memory locations
--
-- - Registers
--
-- Memory locations are referred to by on of several addressing modes:
--
-- - Absolute (address in instruction stream)
--
-- - Register-indirect (address in register)
--
-- - Register-indirect with displacement
--
-- - Base-Index with scale
--
-- - Base-Index with scale and displacement 
--
-- Displacements can be encoded as 8 or 32-bit immediates in the
-- instruction stream, but are encoded as Int in instructions for
-- simplicity.
--
data Operand = OpImm Word32		-- ^ Immediate value
              | OpAddr Word32 InstrOperandSize -- ^ Absolute address
              | OpReg String Int	-- ^ Register
              | OpFPReg Int		-- ^ Floating-point register
              | OpInd String InstrOperandSize -- ^Register-indirect
              | OpIndDisp String Int InstrOperandSize
	        -- ^ Register-indirect with displacement
              | OpBaseIndex String String Int InstrOperandSize
        				-- ^ Base plus scaled index
              | OpIndexDisp String Int Int InstrOperandSize
       		 -- ^ Scaled index with displacement
              | OpBaseIndexDisp String String Int Int InstrOperandSize
       		 -- ^ Base plus scaled index with displacement
  deriving (Eq)

-- Show an operand in AT&T style.

showAttOps (OpImm w) = showImm w
showAttOps (OpAddr w _) = showAddr w
showAttOps (OpReg s num) = "%" ++ s
showAttOps (OpFPReg 0) = "%st"
showAttOps (OpFPReg i) = "%st(" ++ show i ++ ")"
showAttOps (OpInd s _) = "(%" ++ s ++ ")"
showAttOps (OpIndDisp s disp _) = show disp ++ "(%" ++ s ++ ")"
showAttOps (OpBaseIndex b i s _) = "(%" ++ b ++ ",%" ++ i ++ "," ++ show s ++ ")"
showAttOps (OpIndexDisp i s disp _) = show disp ++ "(%" ++ i ++ "," ++ 
  show s ++ ")"
showAttOps (OpBaseIndexDisp b i s disp _) = show disp ++ "(%" ++ b ++ ",%" ++ 
  i ++ "," ++ show s ++ ")"

-- Show an operand in Intel style.

showIntelOps opsize (OpImm w) = showIntelImm w
showIntelOps opsize (OpAddr w sz) = opInd sz ++ "[" ++ showIntelAddr w ++ "]"
showIntelOps opsize (OpReg s num) = s
showIntelOps opsize (OpFPReg 0) = "st"
showIntelOps opsize (OpFPReg i) = "st(" ++ show i ++ ")"
showIntelOps opsize (OpInd s sz) = opInd sz ++ "[" ++ s ++ "]"
showIntelOps opsize (OpIndDisp s disp sz) = 
    opInd sz ++ "[" ++ s ++ 
       (if disp < 0 then "" else "+") ++ show disp ++ "]"
showIntelOps opsize (OpBaseIndex b i s sz) = 
    opInd sz ++ "[" ++ b ++ "+" ++ i ++ "*" ++ show s ++ "]"
showIntelOps opsize (OpIndexDisp i s disp sz) = 
    opInd sz ++ "[" ++ i ++ "*" ++ show s ++ 
       (if disp < 0 then "" else "+") ++ show disp ++ "]"
showIntelOps opsize (OpBaseIndexDisp b i s disp sz) = 
    opInd sz ++ "[" ++ b ++ "+" ++ i ++ "*" ++ show s ++ 
       (if disp < 0 then "" else "+") ++ 
      show disp ++ "]"
opInd OPNONE = ""
opInd OP8 = "byte ptr "
opInd OP16 = "word ptr "
opInd OP32 = "dword ptr "
opInd OPF32 = "dword ptr "
opInd OP64 = "qword ptr "
opInd OPF64 = "qword ptr "
opInd OPF80 = "tbyte ptr "
opInd OP128 = "dqword ptr "

-- | Encodes the default and currently active operand or address size.  Can
-- be changed with the operand- or address-size prefixes 0x66 and 0x67.

data OperandSize = BIT16 | BIT32

-- | Some opcodes can operate on data of several widths.  This information
-- is encoded in instructions using the following enumeration type..

data InstrOperandSize = OPNONE -- ^ No operand size specified
       	        | OP8 	       -- ^ 8-bit integer operand
       	        | OP16 	       -- ^ 16-bit integer operand
       	        | OP32	       -- ^ 32-bit integer operand
       	        | OP64	       -- ^ 64-bit integer operand
       	        | OP128	       -- ^ 128-bit integer operand
       	        | OPF32	       -- ^ 32-bit floating point operand
       	        | OPF64	       -- ^ 64-bit floating point operand
       	        | OPF80	       -- ^ 80-bit floating point operand
  deriving (Show, Eq)


-- | The disassembly routines return lists of the following datatype.  It
-- encodes both invalid byte sequences (with a useful error message, if
-- possible), or a valid instruction.  Both variants contain the list of
-- opcode bytes from which the instruction was decoded and the address of
-- the instruction.

data Instruction = 
    BadInstruction Word8 String Int [Word8]   -- ^ Invalid instruction
  | PseudoInstruction Int String                  -- ^ Pseudo instruction, e.g. label
  | Instruction { opcode :: Opcode, 	      -- ^ Opcode of the instruction
       		  opsize :: InstrOperandSize, -- ^ Operand size, if any
       		  operands :: [Operand],      -- ^ Instruction operands
                  address :: Int,             -- ^ Start address of instruction
       		  bytes ::[Word8]	      -- ^ Instruction bytes
                 }			      -- ^ Valid instruction
  deriving (Eq)

instance Show Instruction where
    show = showIntel

data Instr = Bad Word8 String
            | Instr Opcode InstrOperandSize [Operand]

-- Show an integer as an 8-digit hexadecimal number with leading zeroes.

hex32 :: Int -> String
hex32 i =
    let w :: Word32
        w = fromIntegral i
        s = showHex w ""
    in take (8 - length s) (repeat '0') ++ s

-- Show a byte as an 2-digit hexadecimal number with leading zeroes.

hex8 :: Word8 -> String
hex8 i =
    let s = showHex i ""
    in take (2 - length s) ['0','0'] ++ s


-- | Instructions can be displayed either in Intel or AT&T style (like in
-- GNU tools).
--
-- Intel style:
--
-- - Destination operand comes first, source second.
--
-- - No register or immediate prefixes.
--
-- - Memory operands are annotated with operand size.
--
-- - Hexadecimal numbers are suffixed with @H@ and prefixed with @0@ if
--   necessary.
--
-- AT&T style:
--
-- - Source operand comes first, destination second.
--
-- - Register names are prefixes with @%@.
--
-- - Immediates are prefixed with @$@.
--
-- - Hexadecimal numbers are prefixes with @0x@
--
-- - Opcodes are suffixed with operand size, when ambiguous otherwise.
data ShowStyle = IntelStyle		-- ^ Show in Intel style
                | AttStyle		-- ^ Show in AT&T style

-- | Show an instruction in Intel style.

showIntel :: Instruction -> [Char]
showIntel (BadInstruction b desc pos bytes) =
    showPosBytes pos bytes ++
    "(" ++ desc ++ ", byte=" ++ show b ++ ")"
showIntel (PseudoInstruction pos s) =
    hex32 pos ++ "                          " ++ s
showIntel (Instruction op opsize [] pos bytes) = 
    showPosBytes pos bytes ++
       showOp op
showIntel (Instruction op opsize ops pos bytes) = 
    showPosBytes pos bytes ++
        enlarge (showOp op) 6 ++ " " ++
       concat (intersperse "," (map (showIntelOps opsize) ops))

-- | Show an instruction in AT&T style.

showAtt :: Instruction -> [Char]
showAtt (BadInstruction b desc pos bytes) = 
    showPosBytes pos bytes ++
       "(" ++ desc ++ ", byte=" ++ show b ++ ")"
showAtt (PseudoInstruction pos s) =
    hex32 pos ++ "                          " ++ s
showAtt (Instruction op opsize [] pos bytes) = 
    showPosBytes pos bytes ++
       showOp op ++ showInstrSuffix [] opsize
showAtt (Instruction op opsize ops pos bytes) = 
    showPosBytes pos bytes ++
       enlarge (showOp op ++ showInstrSuffix ops opsize) 6 ++ " " ++
       concat (intersperse "," (map showAttOps (reverse ops)))

showPosBytes pos bytes =
    hex32 pos ++ "  " ++ 
      enlarge (concat (intersperse " " (map hex8 bytes))) 30

enlarge s i = s ++ take (i - length s) (repeat ' ')

opSizeSuffix OPNONE = ""
opSizeSuffix OP8 = "b"
opSizeSuffix OP16 = "w"
opSizeSuffix OP32 = "l"
opSizeSuffix OP64 = "q"
opSizeSuffix OP128 = "dq"
opSizeSuffix OPF32 = "s"
opSizeSuffix OPF64 = "l"
opSizeSuffix OPF80 = "t"

showInstrSuffix [] sz = opSizeSuffix sz
showInstrSuffix ((OpImm _) : os) s = showInstrSuffix os s
--showInstrSuffix ((OpReg _ _) : []) s = ""
showInstrSuffix ((OpReg _ _) : os) s = showInstrSuffix os OPNONE
showInstrSuffix ((OpFPReg _) : os) s = showInstrSuffix os s
showInstrSuffix ((OpAddr _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpAddr _ sz) : os) s = opSizeSuffix sz
showInstrSuffix ((OpInd _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpInd _ sz) : os) s = opSizeSuffix sz
showInstrSuffix ((OpIndDisp _ _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpIndDisp _ _ sz) : os) s = opSizeSuffix sz
showInstrSuffix ((OpBaseIndex _ _ _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpBaseIndex _ _ _ sz) : os) s = opSizeSuffix sz
showInstrSuffix ((OpIndexDisp _ _ _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpIndexDisp _ _ _ sz) : os) s = opSizeSuffix sz
showInstrSuffix ((OpBaseIndexDisp _ _ _ _ OPNONE) : os) s = showInstrSuffix os s
showInstrSuffix ((OpBaseIndexDisp _ _ _ _ sz) : os) s = opSizeSuffix sz

-- showInstrOperandSize ops OPNONE | noRegop ops = ""
-- showInstrOperandSize ops OP8 | noRegop ops = "b"
-- showInstrOperandSize ops OP16 | noRegop ops = "w"
-- showInstrOperandSize ops OP32 | noRegop ops = "l"
-- showInstrOperandSize ops OPF32 | noRegop ops = "s"
-- showInstrOperandSize ops OP64 | noRegop ops = "q"
-- showInstrOperandSize ops OPF64 | noRegop ops = "l"
-- showInstrOperandSize ops OPF80 | noRegop ops = "e"
-- showInstrOperandSize ops OP128 | noRegop ops = ""
-- showInstrOperandSize _ _ = ""

-- noRegop ops = null (filter isRegop ops)
-- isRegop (OpReg _ _) = True
-- isRegop _ = False

-- Show an immediate value in hexadecimal.

showImm :: Word32 -> String
showImm i =
  "$0x" ++ showHex i ""

showIntelImm :: Word32 -> String
showIntelImm i =
  let h = showHex i "H"
      (f:_) = h
  in (if isDigit f then "" else "0") ++ h

-- Show an address in hexadecimal.

showAddr i =  
  let w :: Word32
      w = fromIntegral i
  in "0x" ++ showHex w ""
showIntelAddr i = 
  let w :: Word32
      w = fromIntegral i
      h = showHex w "H"
      (f:_) = h
  in (if isDigit f then "" else "0") ++ h

-- | Disassemble a block of memory.  Starting at the location
-- pointed to by the given pointer, the given number of bytes are
-- disassembled.

disassembleBlock :: Ptr Word8 -> Int -> IO (Either ParseError [Instruction])
disassembleBlock ptr len = 
    disassembleBlockWithConfig defaultConfig{confStartAddr = fromIntegral (minusPtr ptr nullPtr)} 
                               ptr len

disassembleBlockWithConfig :: Config -> Ptr Word8 -> Int -> IO (Either ParseError [Instruction])
disassembleBlockWithConfig config ptr len = do
  l <- toList ptr len 0 []
  parseInstructions (configToState config) (reverse l)
  where 
  toList :: (Ptr Word8) -> Int -> Int -> [Word8] -> IO [Word8]
  toList ptr len idx acc | idx < len =
       	   do p <- peekByteOff ptr idx
       	      toList ptr len (idx + 1) (p : acc)
--       	      return (p : r)
  toList ptr len idx acc | idx >= len = return acc

-- | Disassemble the contents of the given array.

disassembleArray :: (Monad m, IArray a Word8, Ix i) =>
                    a i Word8 -> m (Either ParseError [Instruction])
disassembleArray arr = disassembleArrayWithConfig defaultConfig arr

disassembleArrayWithConfig :: (Monad m, IArray a Word8, Ix i) => Config ->
                             a i Word8 -> m (Either ParseError [Instruction])
disassembleArrayWithConfig config arr =
  let l = elems arr
  in parseInstructions (configToState config) l

-- | Disassemble the contents of the given list.

disassembleList :: (Monad m) =>
                   [Word8] -> m (Either ParseError [Instruction])
disassembleList ls = disassembleListWithConfig defaultConfig ls

disassembleListWithConfig :: (Monad m) => Config ->
                   [Word8] -> m (Either ParseError [Instruction])
disassembleListWithConfig config ls =
    parseInstructions (configToState config) ls

disassembleFile filename = disassembleFileWithConfig defaultConfig filename

disassembleFileWithConfig config filename = do
  l <- readFile filename
  parseInstructions (configToState config) (map (fromIntegral . ord) l)

instrToString insts style =
  map showInstr insts
 where
 showInstr = case style of
       	  IntelStyle -> showIntel
       	  AttStyle -> showAtt

-- | Test function for disassembling the contents of a binary file and
-- displaying it in the provided style ("IntelStyle" or "AttStyle").

testFile :: FilePath -> ShowStyle -> IO ()
testFile fname style = do
  l <- readFile fname
  i <- parseInstructions defaultState (map (fromIntegral . ord) l)
  case i of
    Left err -> putStrLn (show err)
    Right i' -> mapM_ (putStrLn . showInstr) i'
 where
 showInstr = case style of
       	  IntelStyle -> showIntel
       	  AttStyle -> showAtt

-- This is the state maintained by the disassembler.

data PState = PState { defaultBitMode :: OperandSize,
       	               operandBitMode :: OperandSize,
       	               addressBitMode :: OperandSize,
       	               in64BitMode :: Bool,
                       prefixes :: [Word8],
       	               startAddr :: Word32
                      }

data Config = Config {confDefaultBitMode :: OperandSize,
                      confOperandBitMode :: OperandSize,
                      confAddressBitMode :: OperandSize,
                      confIn64BitMode        :: Bool,
                      confStartAddr          :: Word32}

defaultConfig = Config{ confDefaultBitMode = BIT32,
       	                confOperandBitMode = BIT32, 
       	                confAddressBitMode = BIT32, 
       	                confIn64BitMode = False,
       	                confStartAddr = 0}

configToState (Config defBitMode opMode addrMode in64 confStartAddr) =
    defaultState{defaultBitMode = defBitMode,
                 operandBitMode = opMode,
                 addressBitMode = addrMode,
                 in64BitMode = in64,
                 startAddr = confStartAddr}
           
-- Default state to be used if no other is given to the disassembly
-- routines.

defaultState = PState { defaultBitMode = BIT32,
       	          operandBitMode = BIT32, 
       	          addressBitMode = BIT32, 
       	          in64BitMode = False,
       	          prefixes = [],
       	          startAddr = 0}

type Word8Parser a = GenParser Word8 PState a

parseInstructions st l =
    return (runParser instructionSequence st "memory block" l)

-- Parse a possibly empty sequence of instructions.

instructionSequence = many instruction

-- Parse a single instruction.  The result is either a valid instruction
-- or an indicator that there starts no valid instruction at the current
-- position.

instruction = do
    startPos' <- getPosition
    let startPos = sourceColumn startPos' - 1
    input <- getInput
    st <- getState
    setState st{operandBitMode = defaultBitMode st,
                 addressBitMode = defaultBitMode st,
               prefixes = []}
    many parsePrefix
    b <- anyWord8
    case lookup b oneByteOpCodeMap of
      Just p -> do i <- p b
       		   endPos' <- getPosition
       		   let endPos = sourceColumn endPos' - 1
		   case i of
       		     Instr oc opsize ops -> do
       	               return $ Instruction oc opsize ops
       		            (fromIntegral (startAddr st) + startPos)
       		            (take (endPos - startPos) input)
       	             Bad b desc ->
       	               return $ BadInstruction b desc 
       		            (fromIntegral (startAddr st) + startPos)
       		            (take (endPos - startPos) input)
      Nothing -> do Bad b desc <- parseInvalidOpcode b
		    endPos' <- getPosition
       		    let endPos = sourceColumn endPos' - 1
       		    return $ BadInstruction b desc 
       	                (fromIntegral (startAddr st) + startPos)
       		        (take (endPos - startPos) input)

toggleBitMode BIT16 = BIT32
toggleBitMode BIT32 = BIT16

rex_B = 0x1
rex_X = 0x2
rex_R = 0x4
rex_W = 0x8

-- Return True if the given REX prefix bit appears in the list of current
-- instruction prefixes, False otherwise.

hasREX rex st =
    let rexs = filter (\ b -> b >= 0x40 && b <= 0x4f) (prefixes st) in
       case rexs of
         (r : _) -> if r .&. rex == rex then True else False
         _ -> False

-- Return True if the given prefix appears in the list of current
-- instruction prefixes, False otherwise.

hasPrefix b st = b `elem` prefixes st

addPrefix b = do
    st <- getState
    setState st{prefixes = b : prefixes st}

-- Parse a single prefix byte and remember it in the parser state.  If in
-- 64-bit mode, accept REX prefixes.

parsePrefix = do
    (word8 0xf0 >>= addPrefix) -- LOCK
  <|>
    (word8 0xf2 >>= addPrefix) -- REPNE/REPNZ
  <|>
    (word8 0xf3 >>= addPrefix) -- REP or REPE/REPZ
  <|>
    (word8 0x2e >>= addPrefix) -- CS segment override
  <|>
    (word8 0x36 >>= addPrefix) -- SS segment override
  <|>
    (word8 0x3e >>= addPrefix) -- DS segment override
  <|>
    (word8 0x26 >>= addPrefix) -- ES segment override
  <|>
    (word8 0x64 >>= addPrefix) -- FS segment override
  <|>
    (word8 0x65 >>= addPrefix) -- GS segment override
  <|>
    (word8 0x2e >>= addPrefix) -- branch not taken
  <|>
    (word8 0x3e >>= addPrefix) -- branch taken
  <|>
    do word8 0x66 -- operand-size override
       st <- getState
       setState st{operandBitMode = toggleBitMode (operandBitMode st)}
       addPrefix 0x66
  <|>
    do word8 0x67 -- address-size override
       st <- getState
       setState st{addressBitMode = toggleBitMode (addressBitMode st)}
       addPrefix 0x66
  <|>  do st <- getState
          if in64BitMode st 
            then    (word8 0x40 >>= addPrefix)
                     <|>
                     (word8 0x41 >>= addPrefix)
                     <|>
                     (word8 0x42 >>= addPrefix)
                     <|>
                     (word8 0x43 >>= addPrefix)
                     <|>
                     (word8 0x44 >>= addPrefix)
                     <|>
                     (word8 0x45 >>= addPrefix)
                     <|>
                     (word8 0x46 >>= addPrefix)
                     <|>
                     (word8 0x47 >>= addPrefix)
                     <|>
                     (word8 0x48 >>= addPrefix)
                     <|>
                     (word8 0x49 >>= addPrefix)
                     <|>
                     (word8 0x4a >>= addPrefix)
                     <|>
                     (word8 0x4b >>= addPrefix)
                     <|>
                     (word8 0x4c >>= addPrefix)
                     <|>
                     (word8 0x4d >>= addPrefix)
                     <|>
                     (word8 0x4e >>= addPrefix)
                     <|>
                     (word8 0x4f >>= addPrefix)
             else pzero

-- Accept the single unsigned byte B.

word8 b = do
    tokenPrim showByte nextPos testByte
  where
  showByte by = show by
  nextPos pos x xs = incSourceColumn pos 1
  testByte by = if b == by then Just by else Nothing

-- Accept and return a single unsigned byte.

anyWord8 :: Word8Parser Word8
anyWord8 = do
    tokenPrim showByte nextPos testByte
  where
  showByte by = show by
  nextPos pos x xs = incSourceColumn pos 1
  testByte by =  Just by

-- Accept any 8-bit signed byte.

anyInt8 :: Word8Parser Int8
anyInt8 = do
   b <- anyWord8
   let i :: Int8
       i = fromIntegral b
   return i

-- Accept any 16-bit unsigned word.

anyWord16 = do
     b0 <- anyWord8
     b1 <- anyWord8
     let w0, w1 :: Word16
         w0 = fromIntegral b0
         w1 = fromIntegral b1
     return $ w0 .|. (w1 `shiftL` 8)

-- Accept any 16-bit signed integer.

anyInt16 = do
     b0 <- anyWord16
     let w0 :: Int16
         w0 = fromIntegral b0
     return $ w0

-- Accept a 32-bit unsigned word.

anyWord32 = do
     b0 <- anyWord16
     b1 <- anyWord16
     let w0, w1 :: Word32
         w0 = fromIntegral b0
         w1 = fromIntegral b1
     return $ w0 .|. (w1 `shiftL` 16)

-- Accept a 32-bit signed integer.

anyInt32 :: Word8Parser Int32
anyInt32 = do
     b0 <- anyWord32
     let w0 :: Int32
         w0 = fromIntegral b0
     return $ w0

-- Accept a 64-bit unsigned word.

anyWord64 :: Word8Parser Word64
anyWord64 = do
     b0 <- anyWord32
     b1 <- anyWord32
     let w0, w1 :: Word64
         w0 = fromIntegral b0
         w1 = fromIntegral b1
     return $ w0 .|. (w1 `shiftL` 32)

-- Accept a 64-bit signed integer.

anyInt64 :: Word8Parser Int64
anyInt64 = do
     b0 <- anyWord64
     let w0 :: Int64
         w0 = fromIntegral b0
     return $ w0

-- Accept a 16-bit word for 16-bit operand-size, a 32-bit word for
-- 32-bit operand-size, or a 64-bit word in 64-bit mode.

anyWordV :: Word8Parser Word64
anyWordV = do
    st <- getState
    if in64BitMode st
       then do w <- anyWord64
               return w
        else case operandBitMode st of
              BIT16 -> do w <- anyWord16
       	                  let w' :: Word64
       	                      w' = fromIntegral w
       	                  return w'
              BIT32 -> do w <- anyWord32
       	                  let w' :: Word64
       	                      w' = fromIntegral w
       	                  return w'

-- Accept a 16-bit word for 16-bit operand-size or a 32-bit word for
-- 32-bit operand-size or 64-bit mode.

anyWordZ :: Word8Parser Word32
anyWordZ = do
    st <- getState
    case operandBitMode st of
      BIT16 -> do 
        w <- anyWord16
       	let w' :: Word32
       	    w' = fromIntegral w
       	return w'
      BIT32 -> anyWord32

-- Accept a 16-bit integer for 16-bit operand-size or a 32-bit word for
-- 32-bit operand-size or 64-bit mode.

anyIntZ :: Word8Parser Int32
anyIntZ = do
    st <- getState
    case operandBitMode st of
      BIT16 -> do 
        w <- anyInt16
       	let w' :: Int32
       	    w' = fromIntegral w
       	return w'
      BIT32 -> anyInt32

-- Accept a 32-bit far address for 16-bit operand-size or a 48-bit far
-- address for 32-bit operand-size.

anyWordP :: Word8Parser Word64
anyWordP = do
    st <- getState
    case operandBitMode st of
      BIT16 -> do w <- anyWord32
       	          let w' :: Word64
       	              w' = fromIntegral w
		  return w'
      _ -> do w1 <- anyWord32
       	      w2 <- anyWord16
              let w1', w2' :: Word64
       	          w1' = fromIntegral w1
                  w2' = fromIntegral w2
       	      return (w1' .|. (w2' `shiftL` 32))

oneByteOpCodeMap =
    [(0x00, parseALU ADD),
     (0x01, parseALU ADD),
     (0x02, parseALU ADD),
     (0x03, parseALU ADD),
     (0x04, parseALU ADD),
     (0x05, parseALU ADD),
     (0x06, invalidIn64BitMode (parsePUSHSeg "es")),
     (0x07, invalidIn64BitMode (parsePOPSeg "es")),
     (0x08, parseALU OR),
     (0x09, parseALU OR),
     (0x0a, parseALU OR),
     (0x0b, parseALU OR),
     (0x0c, parseALU OR),
     (0x0d, parseALU OR),
     (0x0e, invalidIn64BitMode (parsePUSHSeg "cs")),
     (0x0f, twoByteEscape),

     (0x10, parseALU ADC),
     (0x11, parseALU ADC),
     (0x12, parseALU ADC),
     (0x13, parseALU ADC),
     (0x14, parseALU ADC),
     (0x15, parseALU ADC),
     (0x16, invalidIn64BitMode (parsePUSHSeg "ss")),
     (0x17, invalidIn64BitMode (parsePOPSeg "ss")),
     (0x18, parseALU SBB),
     (0x19, parseALU SBB),
     (0x1a, parseALU SBB),
     (0x1b, parseALU SBB),
     (0x1c, parseALU SBB),
     (0x1d, parseALU SBB),
     (0x1e, invalidIn64BitMode (parsePUSHSeg "ds")),
     (0x1f, invalidIn64BitMode (parsePOPSeg "ds")),

     (0x20, parseALU AND),
     (0x21, parseALU AND),
     (0x22, parseALU AND),
     (0x23, parseALU AND),
     (0x24, parseALU AND),
     (0x25, parseALU AND),
     (0x26, parseInvalidPrefix), -- ES segment override prefix
     (0x27, invalidIn64BitMode (parseGeneric DAA OPNONE)),
     (0x28, parseALU SUB),
     (0x29, parseALU SUB),
     (0x2a, parseALU SUB),
     (0x2b, parseALU SUB),
     (0x2c, parseALU SUB),
     (0x2d, parseALU SUB),
     (0x2e, parseInvalidPrefix), -- CS segment override prefix
     (0x2f, invalidIn64BitMode (parseGeneric DAS OPNONE)),

     (0x30, parseALU XOR),
     (0x31, parseALU XOR),
     (0x32, parseALU XOR),
     (0x33, parseALU XOR),
     (0x34, parseALU XOR),
     (0x35, parseALU XOR),
     (0x36, parseInvalidPrefix), -- SS segment override prefix
     (0x37, invalidIn64BitMode (parseGeneric AAA OPNONE)),
     (0x38, parseALU CMP),
     (0x39, parseALU CMP),
     (0x3a, parseALU CMP),
     (0x3b, parseALU CMP),
     (0x3c, parseALU CMP),
     (0x3d, parseALU CMP),
     (0x3e, parseInvalidPrefix), -- DS segment override prefix
     (0x3f, invalidIn64BitMode (parseGeneric AAS OPNONE)),

     (0x40, invalidIn64BitMode parseINC), -- REX Prefix in 64-bit mode
     (0x41, invalidIn64BitMode parseINC), -- ...
     (0x42, invalidIn64BitMode parseINC),
     (0x43, invalidIn64BitMode parseINC),
     (0x44, invalidIn64BitMode parseINC),
     (0x45, invalidIn64BitMode parseINC),
     (0x46, invalidIn64BitMode parseINC),
     (0x47, invalidIn64BitMode parseINC),
     (0x48, invalidIn64BitMode parseDEC),
     (0x49, invalidIn64BitMode parseDEC),
     (0x4a, invalidIn64BitMode parseDEC),
     (0x4b, invalidIn64BitMode parseDEC),
     (0x4c, invalidIn64BitMode parseDEC),
     (0x4d, invalidIn64BitMode parseDEC),
     (0x4e, invalidIn64BitMode parseDEC),
     (0x4f, invalidIn64BitMode parseDEC),

     (0x50, parsePUSH),
     (0x51, parsePUSH),
     (0x52, parsePUSH),
     (0x53, parsePUSH),
     (0x54, parsePUSH),
     (0x55, parsePUSH),
     (0x56, parsePUSH),
     (0x57, parsePUSH),
     (0x58, parsePOP),
     (0x59, parsePOP),
     (0x5a, parsePOP),
     (0x5b, parsePOP),
     (0x5c, parsePOP),
     (0x5d, parsePOP),
     (0x5e, parsePOP),
     (0x5f, parsePOP),

     (0x60, invalidIn64BitMode parsePUSHA),
     (0x61, invalidIn64BitMode parsePOPA),
     (0x62, invalidIn64BitMode parseBOUND),
     (0x63, choose64BitMode parseARPL parseMOVSXD), -- MOVSXD in 64-bit mode
     (0x64, parseInvalidPrefix), -- FS segment override prefix
     (0x65, parseInvalidPrefix), -- GS segment override prefix
     (0x66, parseInvalidPrefix), -- operand-size prefix
     (0x67, parseInvalidPrefix), -- address-size prefix
     (0x68, parsePUSHImm),
     (0x69, parseIMUL),
     (0x6a, parsePUSHImm),
     (0x6b, parseIMUL),
     (0x6c, parseINS),
     (0x6d, parseINS),
     (0x6e, parseOUTS),
     (0x6f, parseOUTS),

     (0x70, parseJccShort),
     (0x71, parseJccShort),
     (0x72, parseJccShort),
     (0x73, parseJccShort),
     (0x74, parseJccShort),
     (0x75, parseJccShort),
     (0x76, parseJccShort),
     (0x77, parseJccShort),
     (0x78, parseJccShort),
     (0x79, parseJccShort),
     (0x7a, parseJccShort),
     (0x7b, parseJccShort),
     (0x7c, parseJccShort),
     (0x7d, parseJccShort),
     (0x7e, parseJccShort),
     (0x7f, parseJccShort),

     (0x80, parseGrp1),
     (0x81, parseGrp1),
     (0x82, invalidIn64BitMode parseGrp1),
     (0x83, parseGrp1),
     (0x84, parseTEST),
     (0x85, parseTEST),
     (0x86, parseXCHG),
     (0x87, parseXCHG),
     (0x88, parseMOV),
     (0x89, parseMOV),
     (0x8a, parseMOV),
     (0x8b, parseMOV),
     (0x8c, parseMOV),
     (0x8d, parseLEA),
     (0x8e, parseMOV),
     (0x8f, parseGrp1A),

     (0x90, parse0x90), -- NOP, PAUSE(F3), XCHG r8,rAX
     (0x91, parseXCHGReg),
     (0x92, parseXCHGReg),
     (0x93, parseXCHGReg),
     (0x94, parseXCHGReg),
     (0x95, parseXCHGReg),
     (0x96, parseXCHGReg),
     (0x97, parseXCHGReg),
     (0x98, parseCBW_CWDE_CDQE),
     (0x99, parseCWD_CDQ_CQO),
     (0x9a, invalidIn64BitMode parseCALLF),
     (0x9b, parseGeneric WAIT OPNONE),
     (0x9c, parsePUSHF),
     (0x9d, parsePOPF),
     (0x9e, parseGeneric SAHF OPNONE),
     (0x9f, parseGeneric LAHF OPNONE),

     (0xa0, parseMOVImm),
     (0xa1, parseMOVImm),
     (0xa2, parseMOVImm),
     (0xa3, parseMOVImm),
     (0xa4, parseMOVS),
     (0xa5, parseMOVS),
     (0xa6, parseCMPS),
     (0xa7, parseCMPS),
     (0xa8, parseTESTImm),
     (0xa9, parseTESTImm),
     (0xaa, parseSTOS),
     (0xab, parseSTOS),
     (0xac, parseLODS),
     (0xad, parseLODS),
     (0xae, parseSCAS),
     (0xaf, parseSCAS),

     (0xb0, parseMOVImmByteToByteReg),
     (0xb1, parseMOVImmByteToByteReg),
     (0xb2, parseMOVImmByteToByteReg),
     (0xb3, parseMOVImmByteToByteReg),
     (0xb4, parseMOVImmByteToByteReg),
     (0xb5, parseMOVImmByteToByteReg),
     (0xb6, parseMOVImmByteToByteReg),
     (0xb7, parseMOVImmByteToByteReg),
     (0xb8, parseMOVImmToReg),
     (0xb9, parseMOVImmToReg),
     (0xba, parseMOVImmToReg),
     (0xbb, parseMOVImmToReg),
     (0xbc, parseMOVImmToReg),
     (0xbd, parseMOVImmToReg),
     (0xbe, parseMOVImmToReg),
     (0xbf, parseMOVImmToReg),

     (0xc0, parseGrp2),
     (0xc1, parseGrp2),
     (0xc2, parseRETN),
     (0xc3, parseRETN),
     (0xc4, invalidIn64BitMode (parseLoadSegmentRegister LES)),
     (0xc5, invalidIn64BitMode (parseLoadSegmentRegister LDS)),
     (0xc6, parseGrp11),
     (0xc7, parseGrp11),
     (0xc8, parseENTER),
     (0xc9, parseGeneric LEAVE OPNONE),
     (0xca, parseGenericIw RETF),
     (0xcb, parseGeneric RETF OPNONE),
     (0xcc, parseGeneric INT3 OPNONE),
     (0xcd, parseGenericIb INT),
     (0xce, parseGeneric INTO OPNONE),
     (0xcf, parseGeneric IRET OPNONE),

     (0xd0, parseGrp2),
     (0xd1, parseGrp2),
     (0xd2, parseGrp2),
     (0xd3, parseGrp2),
     (0xd4, parseGenericIb AAM),
     (0xd5, parseGenericIb AAD),
     (0xd6, parseReserved), -- reserved
     (0xd7, parseGeneric XLAT OPNONE),
     (0xd8, parseESC),
     (0xd9, parseESC),
     (0xda, parseESC),
     (0xdb, parseESC),
     (0xdc, parseESC),
     (0xdd, parseESC),
     (0xde, parseESC),
     (0xdf, parseESC),

     (0xe0, parseGenericJb LOOPNE),
     (0xe1, parseGenericJb LOOPE),
     (0xe2, parseGenericJb LOOP),
     (0xe3, parseGenericJb JCXZ), -- depends on bit mode
     (0xe4, parseINImm),
     (0xe5, parseINImm),
     (0xe6, parseOUTImm),
     (0xe7, parseOUTImm),
     (0xe8, parseGenericJz CALL),
     (0xe9, parseGenericJz JMP),
     (0xea, parseJMPF),
     (0xeb, parseGenericJb JMP),
     (0xec, parseIN),
     (0xed, parseIN),
     (0xee, parseOUT),
     (0xef, parseOUT),

     (0xf0, parseInvalidPrefix), -- LOCK prefix
     (0xf1, parseReserved), -- reserved
     (0xf2, parseInvalidPrefix), -- REPNE prefix
     (0xf3, parseInvalidPrefix), -- REP/REPQ prefix
     (0xf4, parseGeneric HLT OPNONE),
     (0xf5, parseGeneric CMC OPNONE),
     (0xf6, parseGrp3),
     (0xf7, parseGrp3),
     (0xf8, parseGeneric CLC OPNONE),
     (0xf9, parseGeneric STC OPNONE),
     (0xfa, parseGeneric CLI OPNONE),
     (0xfb, parseGeneric STI OPNONE),
     (0xfc, parseGeneric CLD OPNONE),
     (0xfd, parseGeneric STD OPNONE),
     (0xfe, parseGrp4),
     (0xff, parseGrp5)

     ]

parseInvalidPrefix b = do
  return $ Bad b "invalid prefix"

parseInvalidOpcode b = do
  return $ Bad b "invalid opcode"

parseReserved b = do
  return $ Bad b "reserved opcode"

parseUndefined name b = do
  return $ Bad b ("undefined opcode: " ++ show name)

parseUnimplemented b = do
  return $ Bad b "not implemented yet"

invalidIn64BitMode p b = do
  st <- getState
  if in64BitMode st
     then return $ Bad b "invalid in 64-bit mode"
     else p b

onlyIn64BitMode p b = do
  st <- getState
  if in64BitMode st
     then p b
     else return $ Bad b "only in 64-bit mode"

choose64BitMode p32 p64 b = do
  st <- getState
  if in64BitMode st
     then p64 b
     else p32 b

chooseOperandSize p16 p32 b = do
  st <- getState
  case operandBitMode st of
    BIT16 -> p16 b
    BIT32 -> p32 b

chooseAddressSize p16 p32 b = do
  st <- getState
  case addressBitMode st of
    BIT16 -> p16 b
    BIT32 -> p32 b

parseModRM = do
  b <- anyWord8
  parseModRM' b
parseModRM' b = do
  return (b `shiftR` 6, (b `shiftR` 3) .&. 7, (b .&. 7))

parseSIB = do
  b <- anyWord8
  parseSIB' b
parseSIB' b = do
  return (b `shiftR` 6, (b `shiftR` 3) .&. 7, (b .&. 7))

scaleToFactor 0 = 1
scaleToFactor 1 = 2
scaleToFactor 2 = 4
scaleToFactor 3 = 8


parseAddress32 :: InstrOperandSize ->
		  Word8Parser (Operand, Operand, Word8, Word8, Word8)
parseAddress32 s = do
  b <- anyWord8
  parseAddress32' s b

parseAddress32' :: InstrOperandSize -> 
    Word8 ->
    Word8Parser (Operand, Operand, Word8, Word8, Word8)
parseAddress32' opsize modrm = do
  (mod, reg_opc, rm) <- parseModRM' modrm
  st <- getState
  let opregnames = if in64BitMode st && hasREX rex_W st
                     then regnames64
       	      else case operandBitMode st of 
			BIT16 -> regnames16
       			BIT32 -> regnames32
  let addregnames = if in64BitMode st && hasREX rex_R st
                      then regnames64
       	       else case addressBitMode st of 
			BIT16 -> regnames16
       			BIT32 -> regnames32
  case mod of
    0 -> case rm of
            4 -> do 
	     (s, i, b) <- parseSIB
       	     case (i, b) of
               (4, 5) -> do
                           disp <- anyWord32
                           return (OpAddr (fromIntegral disp) opsize,
                                          OpReg (opregnames !! fromIntegral reg_opc)
                                                (fromIntegral reg_opc),
                                          mod, reg_opc, rm)
               (_, 5) -> do
                           disp <- anyWord32
                           return (OpIndexDisp (addregnames !! fromIntegral i)
                                               (scaleToFactor s)
                                               (fromIntegral disp)
                                               opsize,
                                   OpReg (opregnames !! fromIntegral reg_opc)
                                         (fromIntegral reg_opc),
                                   mod, reg_opc, rm)
       	       (4, _) -> return (OpInd (addregnames !! fromIntegral b) opsize,
       	                   OpReg (opregnames !! fromIntegral reg_opc)
			     (fromIntegral reg_opc),
       		           mod, reg_opc, rm)
       	       (_ ,_) -> return (OpBaseIndex 
       		              (addregnames !! fromIntegral b)
       	                      (addregnames !! fromIntegral i)
       		              (scaleToFactor (fromIntegral s))
			      opsize,
       		            OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
       	                    mod, reg_opc, rm)
            5 -> do 
	     disp <- anyWord32
       	     return (OpAddr disp opsize, 
       	             OpReg (opregnames !! fromIntegral reg_opc)
		       (fromIntegral reg_opc),
       	             mod, reg_opc, rm)
            _ -> return (OpInd (addregnames !! fromIntegral rm) opsize, 
       	          OpReg (opregnames !! fromIntegral reg_opc)
			(fromIntegral reg_opc),
       	          mod, reg_opc, rm)
    1 -> case rm of
            4 -> do 
	     (s, i, b) <- parseSIB
	     disp <- anyInt8
       	     case i of
       	       4 -> return (OpIndDisp
       		            (addregnames !! fromIntegral b) 
       		            (fromIntegral disp) opsize,
       	                    OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
       		            mod, reg_opc, rm)
       	       _ -> return (OpBaseIndexDisp
       		            (addregnames !! fromIntegral b)
       		            (addregnames !! fromIntegral i)
       		            (scaleToFactor (fromIntegral s))
       		            (fromIntegral disp)
			    opsize,
       		            OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
       	                    mod, reg_opc, rm)
            _ -> do disp <- anyInt8
                    return (OpIndDisp
       			    (addregnames !! fromIntegral rm) 
       			    (fromIntegral disp)
			    opsize,
       			    OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
                            mod, reg_opc, rm)
    2 -> case rm of
            4 -> do 
	     (s, i, b) <- parseSIB
	     disp <- anyInt32
             case i of
       	       4 -> return (OpIndDisp
       		            (addregnames !! fromIntegral b)
       		            (fromIntegral disp)
			    opsize,
       		            OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
       		            mod, reg_opc, rm)
       	       _ -> return (OpBaseIndexDisp
       		            (addregnames !! fromIntegral b)
       		            (addregnames !! fromIntegral i)
       		            (scaleToFactor (fromIntegral s))
       		            (fromIntegral disp)
			    opsize,
       		            OpReg (opregnames !! fromIntegral reg_opc)
			      (fromIntegral reg_opc),
       	                    mod, reg_opc, rm)
            _ -> do 
	     disp <- anyInt32
       	     return (OpIndDisp
       	             (addregnames !! fromIntegral rm)
       	             (fromIntegral disp)
		     opsize,
       	             OpReg (opregnames !! fromIntegral reg_opc)
		       (fromIntegral reg_opc),
       	             mod, reg_opc, rm)
    3 -> return (OpReg (opregnames !! fromIntegral rm)
		   (fromIntegral rm),
                  OpReg (opregnames !! fromIntegral reg_opc)
		    (fromIntegral reg_opc),
                 mod, reg_opc, rm)

parseALU :: Opcode -> Word8 -> Word8Parser Instr
parseALU op b = do
    opsize <- instrOperandSize
    case b .&. 0x07 of
      0 -> do (op1, op2, mod, reg, rm) <- parseAddress32 opsize
              return $ Instr op OP8 [op1,
       	           (OpReg (regnames8 !! fromIntegral reg)) (fromIntegral reg)]
      1 -> do (op1, op2, mod, reg, rm) <- parseAddress32 opsize
              return $ Instr op opsize [op1, op2]
      2 -> do (op1, op2, mod, reg, rm) <- parseAddress32 opsize
              return $ Instr op OP8 
       	           [(OpReg (regnames8 !! fromIntegral reg))
		       (fromIntegral reg), op1]
      3 -> do (op1, op2, mod, reg, rm) <- parseAddress32 opsize
              return $ Instr op opsize [op2, op1]
      4 -> do b <- anyWord8
              return $ Instr op OP8 [(OpReg "al" 0), (OpImm (fromIntegral b))]
      5 -> do b <- anyWordZ
              rn <- registerName 0
              return $ Instr op opsize [(OpReg rn 0), (OpImm b)]
      _ -> return $ Bad b "no ALU opcode (internal error)"
    

parsePUSHSeg :: String -> Word8 -> Word8Parser Instr
parsePUSHSeg r _ = do
     return $ Instr PUSH OP16 [(OpReg r 0)] -- FIXME: register number

parsePOPSeg :: String -> Word8 -> Word8Parser Instr
parsePOPSeg r _ = do
     return $ Instr POP OP16 [(OpReg r 0)] -- FIXME: register number

parseGenericGvEw name b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP16
  case op1 of
    OpReg _ num -> return $ Instr name OP16 [op2, 
					       OpReg (regnames16 !! num) num]
    _ -> return $ Instr name OP8 [op2, op1]

parseGenericGvEb name b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  case op1 of
    OpReg _ num -> return $ Instr name OP8 [op2, 
					       OpReg (regnames8 !! num) num]
    _ -> return $ Instr name OP8 [op2, op1]

parseGenericGvEv name b = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr name opsize [op2, op1]

parseGenericEvGv name b = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr name opsize [op1, op2]

parseGenericEbGb name b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr name OP8 [op1, (OpReg (regnames8 !! fromIntegral reg)
				(fromIntegral reg))]

parseGenericEv name b = do
  opsize <- instrOperandSize
  (op1, op2, mod, _, rm) <- parseAddress32 opsize
  return $ Instr name opsize [op1]

twoByteOpCodeMap = 
    [(0x00, parseGrp6),
     (0x01, parseGrp7),
     (0x02, parseGenericGvEw LAR),
     (0x03, parseGenericGvEw LSL),
     (0x04, parseReserved),
     (0x05, onlyIn64BitMode (parseGeneric SYSCALL OPNONE)),
     (0x06, parseGeneric CLTS OPNONE),
     (0x07, onlyIn64BitMode (parseGeneric SYSCALL OPNONE)),
     (0x08, parseGeneric INVD OPNONE),
     (0x09, parseGeneric WBINVD OPNONE),
     (0x0a, parseReserved),
     (0x0b, parseUndefined UD2),
     (0x0c, parseReserved),
     (0x0d, parseGenericEv NOP),
     (0x0e, parseReserved),
     (0x0f, parseReserved),

     (0x10, parseMOVUPS),
     (0x11, parseMOVUPS),
     (0x12, parseMOVLPS),
     (0x13, parseMOVLPS),
     (0x14, parseUNPCKLPS),
     (0x15, parseUNPCKHPS),
     (0x16, parseMOVHPS),
     (0x17, parseMOVHPS),
     (0x18, parseGrp16),
     (0x19, parseReserved),
     (0x1a, parseReserved),
     (0x1b, parseReserved),
     (0x1c, parseReserved),
     (0x1d, parseReserved),
     (0x1e, parseReserved),
     (0x1f, parseGenericEv NOP),

     (0x20, parseMOVCtrlDebug),
     (0x21, parseMOVCtrlDebug),
     (0x22, parseMOVCtrlDebug),
     (0x23, parseMOVCtrlDebug),
     (0x24, parseReserved),
     (0x25, parseReserved),
     (0x26, parseReserved),
     (0x27, parseReserved),
     (0x28, parseMOVAPS),
     (0x29, parseMOVAPS),
     (0x2a, parseCVTI2PS),
     (0x2b, parseMOVNTPS),
     (0x2c, parseCVTTPS2PI),
     (0x2d, parseCVTPS2PI),
     (0x2e, parseUCOMISS),
     (0x2f, parseCOMISS),

     (0x30, parseGeneric WRMSR OPNONE),
     (0x31, parseGeneric RDTSC OPNONE),
     (0x32, parseGeneric RDMSR OPNONE),
     (0x33, parseGeneric RDPMC OPNONE),
     (0x34, parseGeneric SYSENTER OPNONE),
     (0x35, parseGeneric SYSEXIT OPNONE),
     (0x36, parseReserved),
     (0x37, parseReserved),
     (0x38, parseReserved),
     (0x39, parseReserved),
     (0x3a, parseReserved),
     (0x3b, parseReserved),
     (0x3c, parseReserved),
     (0x3d, parseReserved),
     (0x3e, parseReserved),
     (0x3f, parseReserved),

     (0x40, parseCMOVcc),
     (0x41, parseCMOVcc),
     (0x42, parseCMOVcc),
     (0x43, parseCMOVcc),
     (0x44, parseCMOVcc),
     (0x45, parseCMOVcc),
     (0x46, parseCMOVcc),
     (0x47, parseCMOVcc),
     (0x48, parseCMOVcc),
     (0x49, parseCMOVcc),
     (0x4a, parseCMOVcc),
     (0x4b, parseCMOVcc),
     (0x4c, parseCMOVcc),
     (0x4d, parseCMOVcc),
     (0x4e, parseCMOVcc),
     (0x4f, parseCMOVcc),

     (0x50, parseMOVSKPS),
     (0x51, parseSQRTPS),
     (0x52, parseRSQRTPS),
     (0x53, parseRCPPS),
     (0x54, parseANDPS),
     (0x55, parseANDNPS),
     (0x56, parseORPS),
     (0x57, parseXORPS),
     (0x58, parseADDPS),
     (0x59, parseMULPS),
     (0x5a, parseCVTPS2PD),
     (0x5b, parseCVTDQ2PS),
     (0x5c, parseSUBPS),
     (0x5d, parseMINPS),
     (0x5e, parseDIVPS),
     (0x5f, parseMAXPS),

     (0x60, parsePUNPCKLBW),
     (0x61, parsePUNPCKLWD),
     (0x62, parsePUNPCKLDQ),
     (0x63, parsePACKSSWB),
     (0x64, parsePCMPGTB),
     (0x65, parsePCMPGTW),
     (0x66, parsePCMPGTD),
     (0x67, parsePACKUSWB),
     (0x68, parsePUNPCKHBW),
     (0x69, parsePUNPCKHWD),
     (0x6a, parsePUNPCKHDQ),
     (0x6b, parsePACKSSDW),
     (0x6c, parsePUNPCKLQDQ),
     (0x6d, parsePUNPCKHQDQ),
     (0x6e, parseMOVD_Q),
     (0x6f, parseMOVQ),

     (0x70, parsePSHUFW),
     (0x71, parseGrp12),
     (0x72, parseGrp13),
     (0x73, parseGrp14),
     (0x74, parsePCMPEQB),
     (0x75, parsePCMPEQW),
     (0x76, parsePCMPEQD),
     (0x77, parseGeneric EMMS OPNONE),
     (0x78, parseVMREAD),
     (0x79, parseVMWRITE),
     (0x7a, parseReserved),
     (0x7b, parseReserved),
     (0x7c, parseHADDPS),
     (0x7d, parseHSUBPS),
     (0x7e, parseMOVD_Q),
     (0x7f, parseMOVQ),

     (0x80, parseJccLong),
     (0x81, parseJccLong),
     (0x82, parseJccLong),
     (0x83, parseJccLong),
     (0x84, parseJccLong),
     (0x85, parseJccLong),
     (0x86, parseJccLong),
     (0x87, parseJccLong),
     (0x88, parseJccLong),
     (0x89, parseJccLong),
     (0x8a, parseJccLong),
     (0x8b, parseJccLong),
     (0x8c, parseJccLong),
     (0x8d, parseJccLong),
     (0x8e, parseJccLong),
     (0x8f, parseJccLong),

     (0x90, parseSETcc),
     (0x91, parseSETcc),
     (0x92, parseSETcc),
     (0x93, parseSETcc),
     (0x94, parseSETcc),
     (0x95, parseSETcc),
     (0x96, parseSETcc),
     (0x97, parseSETcc),
     (0x98, parseSETcc),
     (0x99, parseSETcc),
     (0x9a, parseSETcc),
     (0x9b, parseSETcc),
     (0x9c, parseSETcc),
     (0x9d, parseSETcc),
     (0x9e, parseSETcc),
     (0x9f, parseSETcc),

     (0xa0, parsePUSHSeg "fs"),
     (0xa1, parsePOPSeg "fs"),
     (0xa2, parseGeneric CPUID OPNONE),
     (0xa3, parseGenericEvGv BT),
     (0xa4, parseSHLD),
     (0xa5, parseSHLD),
     (0xa6, parseReserved),
     (0xa7, parseReserved),
     (0xa8, parsePUSHSeg "gs"),
     (0xa9, parsePOPSeg "gs"),
     (0xaa, parseGeneric RSM OPNONE),
     (0xab, parseGenericEvGv BTS),
     (0xac, parseSHRD),
     (0xad, parseSHRD),
     (0xae, parseGrp15),
     (0xaf, parseGenericGvEv IMUL),

     (0xb0, parseGenericEbGb CMPXCHG),
     (0xb1, parseGenericEvGv CMPXCHG),
     (0xb2, parseLoadSegmentRegister LSS),
     (0xb3, parseGenericEvGv BTR),
     (0xb4, parseLoadSegmentRegister LFS),
     (0xb5, parseLoadSegmentRegister LGS),
     (0xb6, parseGenericGvEb MOVZXB),
     (0xb7, parseGenericGvEw MOVZXW),
     (0xb8, parseReserved),
     (0xb9, parseGrp10),
     (0xba, parseGrp8),
     (0xbb, parseGenericEvGv BTC),
     (0xbc, parseGenericGvEv BSF),
     (0xbd, parseGenericGvEv BSR),
     (0xbe, parseGenericGvEb MOVSXB),
     (0xbf, parseGenericGvEw MOVSXW),

     (0xc0, parseGenericEbGb XADD),
     (0xc1, parseGenericEvGv XADD),
     (0xc2, parseCMPPS),
     (0xc3, parseMOVNTI),
     (0xc4, parsePINSRW),
     (0xc5, parsePEXTRW),
     (0xc6, parseSHUFPS),
     (0xc7, parseGrp9),
     (0xc8, parseBSWAP),
     (0xc9, parseBSWAP),
     (0xca, parseBSWAP),
     (0xcb, parseBSWAP),
     (0xcc, parseBSWAP),
     (0xcd, parseBSWAP),
     (0xce, parseBSWAP),
     (0xcf, parseBSWAP),

     (0xd0, parseADDSUBPS),
     (0xd1, parsePSRLW),
     (0xd2, parsePSRLD),
     (0xd3, parsePSRLQ),
     (0xd4, parsePADDQ),
     (0xd5, parsePMULLW),
     (0xd6, parseMOVQ),
     (0xd7, parsePMOVMSKB),
     (0xd8, parsePSUBUSB),
     (0xd9, parsePSUBUSW),
     (0xda, parsePMINUB),
     (0xdb, parsePAND),
     (0xdc, parsePADDUSB),
     (0xdd, parsePADDUSW),
     (0xde, parsePMAXUB),
     (0xdf, parsePANDN),

     (0xe0, parsePAVGB),
     (0xe1, parsePSRAW),
     (0xe2, parsePSRAD),
     (0xe3, parsePAVGW),
     (0xe4, parsePMULHUW),
     (0xe5, parsePMULHW),
     (0xe6, parseCVTPD2DQ),
     (0xe7, parseMOVNTQ),
     (0xe8, parsePSUBSB),
     (0xe9, parsePSUBSQ),
     (0xea, parsePMINSW),
     (0xeb, parsePOR),
     (0xec, parsePADDSB),
     (0xed, parsePADDSW),
     (0xee, parsePMAXSW),
     (0xef, parsePXOR),

     (0xf0, parseLDDQU),
     (0xf1, parsePSLLW),
     (0xf2, parsePSLLD),
     (0xf3, parsePSLLQ),
     (0xf4, parsePMULUDQ),
     (0xf5, parsePMADDWD),
     (0xf6, parsePSADBW),
     (0xf7, parseMASKMOVQ),
     (0xf8, parsePSUBB),
     (0xf9, parsePSUBW),
     (0xfa, parsePSUBD),
     (0xfb, parsePSUBQ),
     (0xfc, parsePADDB),
     (0xfd, parsePADDW),
     (0xfe, parsePADDD),
     (0xff, parseReserved)
     ]

twoByteEscape :: Word8 -> Word8Parser Instr
twoByteEscape b1 = do
  b <- anyWord8
  case lookup b twoByteOpCodeMap of
    Just p -> p b
    Nothing -> return $ Bad b "invalid two-byte opcode"

parseGeneric name opsize _ = do
    return (Instr name opsize [])
parseGenericIb name b = do
    b <-  anyWord8
    return $ Instr name OP8 [OpImm (fromIntegral b)]
parseGenericIw name _ = do
    w <- anyWord16
    pos <- getPosition
    return $ Instr name OP16 [OpImm (fromIntegral w)]
parseGenericJb name _ = do
    b <- anyInt8
    pos <- getPosition
    st <- getState
    return $ Instr name OPNONE 
        [OpAddr (fromIntegral ((fromIntegral b + sourceColumn pos - 1)) +
       		(startAddr st)) OPNONE]
parseGenericJz name _ = do
    b <- anyIntZ
    pos <- getPosition
    st <- getState
    return $ Instr name OPNONE 
        [OpAddr (fromIntegral ((fromIntegral b + sourceColumn pos - 1)) +
       	       (startAddr st)) OPNONE]

parseINC b = do
  opsize <- instrOperandSize
  let reg = b .&. 0x0f
  rn <- registerName (fromIntegral reg)
  return $ Instr INC opsize [OpReg rn (fromIntegral reg)]

parseDEC b = do
  opsize <- instrOperandSize
  let reg = (b .&. 0x0f) - 8
  rn <- registerName (fromIntegral reg)
  return $ Instr DEC opsize [OpReg rn (fromIntegral reg)]

parsePUSH b = 
    let reg = b .&. 0x0f in do
      st <- getState
      rn <- registerName (fromIntegral reg)
      opsize <- instrOperandSize
      if hasREX rex_R st
         then return $ Instr PUSH opsize [OpReg ("r" ++ show (reg + 8))
					   (fromIntegral reg)]
          else return $ Instr PUSH opsize [OpReg rn
					    (fromIntegral reg)]

parsePOP b = 
    let reg = (b .&. 0x0f) - 8 in do
      st <- getState
      rn <- registerName (fromIntegral reg)
      opsize <- instrOperandSize
      if hasREX rex_R st
         then return $ Instr POP opsize [OpReg ("r" ++ show (reg + 8))
					 (fromIntegral reg)]
          else return $ Instr POP opsize [OpReg rn (fromIntegral reg)]

parsePUSHA = do
  chooseOperandSize
    (\ _ -> return $ Instr PUSHA OPNONE [])
    (\ _ -> return $ Instr PUSHAD OPNONE [])
parsePOPA = do
  chooseOperandSize
    (\ _ -> return $ Instr POPA OPNONE [])
    (\ _ -> return $ Instr POPAD OPNONE [])

parseBOUND b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  return $ Instr BOUND OPNONE [op2, op1]
  
parseARPL b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP16
  let rn = regnames16 !! fromIntegral reg
  return $ Instr ARPL OPNONE [op1, (OpReg rn (fromIntegral reg))]
     
parseMOVSXD b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  return $ Instr MOVSXD OPNONE [op2, op1]

parsePUSHImm 0x68 = do
  w <- anyWordZ
  opsize <- instrOperandSize
  return $ Instr PUSH opsize [OpImm w]
parsePUSHImm 0x6a = do
  w <- anyWord8
  opsize <- instrOperandSize
  return $ Instr PUSH opsize [OpImm (fromIntegral w)]

parseIMUL 0x69 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  imm <- anyWordZ
  return $ Instr IMUL opsize [op2, op1, OpImm imm]
parseIMUL 0x6b = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  imm <- anyWord8
  return $ Instr IMUL opsize [op2, op1, OpImm (fromIntegral imm)]

parseINS 0x6c = return $ Instr INS OP8 []
parseINS b@0x6d = chooseOperandSize
                   (\ _ -> return $ Instr INS OP16 [])
                  (\ _ -> return $ Instr INS OP32 []) b

parseOUTS 0x6e = return $ Instr OUTS OP8 []
parseOUTS b@0x6f = chooseOperandSize
                     (\ _ -> return $ Instr OUTS OP16 [])
                     (\ _ -> return $ Instr OUTS OP32 []) b

parseJccShort b = do
  disp <- anyInt8
  pos <- getPosition
  st <- getState
  return $ Instr (jccname (b .&. 0xf)) OPNONE
        [OpAddr (fromIntegral (fromIntegral disp + sourceColumn pos - 1) +
                (startAddr st)) OPNONE]

parseTEST 0x84 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr TEST OP8 [op1, OpReg (regnames8 !! fromIntegral reg)
			  (fromIntegral reg)]
parseTEST 0x85 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr TEST opsize [op1, op2]

parseXCHG 0x86 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr XCHG OP8 [op1, OpReg (regnames8 !! fromIntegral reg)
			   (fromIntegral reg)]
parseXCHG 0x87 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr XCHG opsize[op1, op2]

parseMOV 0x88  = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr MOV OP8 [op1, OpReg (regnames8 !! fromIntegral reg)
			  (fromIntegral reg)]
parseMOV 0x89  = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr MOV opsize [op1, op2]
parseMOV 0x8a  = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr MOV OP8 [OpReg (regnames8 !! fromIntegral reg) 
			  (fromIntegral reg), op1]
parseMOV 0x8b  = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr MOV opsize [op2, op1]
parseMOV 0x8c  = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP16
  let rn = segregnames !! (fromIntegral reg)
  return $ Instr MOV OP16 [op1, OpReg rn (fromIntegral reg)]
parseMOV 0x8e  = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP16
  let rn = segregnames !! (fromIntegral reg)
  return $ Instr MOV OP16 [OpReg rn (fromIntegral reg), op1]

parseLEA b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  return $ Instr LEA OPNONE [op2, op1]


parse0x90 b = do
  st <- getState
  if hasPrefix 0xf3 st
     then return $ Instr PAUSE OPNONE []
     else do st <- getState
             if in64BitMode st
                then parseXCHGReg b
       		else return $ Instr NOP OPNONE []

-- FIXME: Register name handling not quite right

parseXCHGReg :: Word8 -> Word8Parser Instr
parseXCHGReg b = 
    let reg = b .&. 0x0f in do
      st <- getState
      if hasREX rex_R st
         then return $ Instr XCHG OP64 [OpReg "rax" 0, 
       					OpReg ("r" ++ show (reg + 8))
					(fromIntegral reg)]
         else do rn <- registerName (fromIntegral reg)
       		 return $ Instr XCHG OP64 [OpReg "rax" 0,
					   OpReg rn (fromIntegral reg)]

parseCBW_CWDE_CDQE b = do
  st <- getState
  if in64BitMode st
     then if hasREX rex_W st
             then return $ Instr CDQE OPNONE []
              else return $ Instr CWDE OPNONE []
     else chooseOperandSize
            (\ _ -> return $ Instr CBW OPNONE [])
            (\ _ -> return $ Instr CWDE OPNONE []) b

parseCWD_CDQ_CQO b = do
  st <- getState
  if in64BitMode st
     then if hasREX rex_W st
             then return $ Instr CDQE OPNONE []
              else return $ Instr CDQ OPNONE []
     else chooseOperandSize
            (\ _ -> return $ Instr CWD OPNONE [])
            (\ _ -> return $ Instr CDQ OPNONE []) b

parseCALLF b = do
    w <- anyWord32
    s <- anyWord16
    return $ Instr CALLF OPNONE [OpImm (fromIntegral w),
       		           OpImm (fromIntegral s)]

-- FIXME: Check default/operand sizes.

parsePUSHF b = do
  st <- getState
  if in64BitMode st
     then chooseOperandSize
             (\ _ -> return $ Instr PUSHF OPNONE [])
             (\ _ -> return $ Instr PUSHFQ OPNONE []) b
     else chooseOperandSize
             (\ _ -> return $ Instr PUSHF OPNONE [])
             (\ _ -> return $ Instr PUSHFD OPNONE []) b

parsePOPF b = do
  st <- getState
  if in64BitMode st
     then chooseOperandSize
             (\ _ -> return $ Instr POPF OPNONE [])
             (\ _ -> return $ Instr POPFQ OPNONE []) b
     else chooseOperandSize
             (\ _ -> return $ Instr POPF OPNONE [])
             (\ _ -> return $ Instr POPFD OPNONE []) b

parseJMPF b = do
    w <- anyWord32
    return $ Instr JMPF OPNONE [OpImm w]

parseMOVImm b@0xa0 = do
  chooseAddressSize
    (\ _ -> do w <- anyWord16
               return $ Instr MOV OP8 [OpReg "al" 0, OpImm (fromIntegral w)])
    (\ _ -> do w <- anyWord32
               return $ Instr MOV OP8 [OpReg "al" 0, OpImm w]) b
parseMOVImm b@0xa1 = do
  opsize <- instrOperandSize
  reg <- registerName 0
  chooseAddressSize
    (\ _ -> do w <- anyWord16
               return $ Instr MOV opsize [OpReg reg 0, OpImm (fromIntegral w)])
    (\ _ -> do w <- anyWord32
       	       return $ Instr MOV opsize [OpReg reg 0, OpImm w]) b
parseMOVImm b@0xa2 = do
  chooseAddressSize
    (\ _ -> do w <- anyWord16
       	       return $ Instr MOV OP8 [OpImm (fromIntegral w), OpReg "al" 0])
    (\ _ -> do w <- anyWord32
       	       return $ Instr MOV OP8 [OpImm w, OpReg "al" 0]) b
parseMOVImm b@0xa3 = do
  opsize <- instrOperandSize
  reg <- registerName 0
  chooseAddressSize
    (\ _ -> do w <- anyWord16
       	       return $ Instr MOV opsize [OpImm (fromIntegral w), OpReg reg 0])
    (\ _ -> do w <- anyWord32
               return $ Instr MOV opsize [OpImm w, OpReg reg 0]) b

parseMOVS 0xa4 = return $ Instr MOVS OP8 []
parseMOVS b@0xa5 = do
  st <- getState
  opsize <- instrOperandSize
  return $ Instr MOVS opsize []

parseCMPS 0xa6 = return $ Instr CMPS OP8 []
parseCMPS 0xa7 = do
  st <- getState
  opsize <- instrOperandSize
  return $ Instr CMPS opsize []

parseTESTImm 0xa8 = do
  imm <- anyWord8
  return $ Instr TEST OP8 [OpReg "al" 0, OpImm (fromIntegral imm)]
parseTESTImm 0xa9 = do
  imm <- anyWordZ
  rn <- registerName 0
  opsize <- instrOperandSize
  return $ Instr TEST opsize [OpReg rn 0, OpImm imm]
  

parseSTOS 0xaa = return $ Instr STOS OP8 []
parseSTOS b@0xab = do
  st <- getState
  opsize <- instrOperandSize
  if in64BitMode st
     then if hasREX rex_W st
             then return $ Instr STOS opsize []
              else chooseOperandSize
                    (\ _ -> return $ Instr STOS opsize [])
                    (\ _ -> return $ Instr STOS opsize []) b
     else chooseOperandSize
            (\ _ -> return $ Instr STOS opsize [])
            (\ _ -> return $ Instr STOS opsize []) b

parseLODS 0xac = return $ Instr LODS OP8 []
parseLODS b@0xad = do
  st <- getState
  opsize <- instrOperandSize
  if in64BitMode st
     then if hasREX rex_W st
             then return $ Instr LODS opsize []
              else chooseOperandSize
                    (\ _ -> return $ Instr LODS opsize [])
                    (\ _ -> return $ Instr LODS opsize []) b
     else chooseOperandSize
            (\ _ -> return $ Instr LODS opsize [])
            (\ _ -> return $ Instr LODS opsize []) b

parseSCAS 0xae = return $ Instr SCAS OP8 []
parseSCAS b@0xaf = do
  st <- getState
  opsize <- instrOperandSize
  if in64BitMode st
     then if hasREX rex_W st
             then return $ Instr SCAS opsize []
              else chooseOperandSize
                    (\ _ -> return $ Instr SCAS opsize [])
                    (\ _ -> return $ Instr SCAS opsize []) b
     else chooseOperandSize
            (\ _ -> return $ Instr SCAS opsize [])
            (\ _ -> return $ Instr SCAS opsize []) b

parseMOVImmByteToByteReg :: Word8 -> Word8Parser Instr
parseMOVImmByteToByteReg b = do
  let reg = b .&. 0x0f
  st <- getState
  imm <- anyWord8
  if hasREX rex_R st
     then return $ Instr MOV OP8 [OpReg ("r" ++ show reg ++ "l")
				   (fromIntegral reg),
       				  OpImm (fromIntegral imm)]
     else return $ Instr MOV OP8 [OpReg (regnames8 !! (fromIntegral reg))
				    (fromIntegral reg), 
       				  OpImm (fromIntegral imm)]

parseMOVImmToReg :: Word8 -> Word8Parser Instr
parseMOVImmToReg b = do
  let reg = (b .&. 0x0f - 8)
  imm <- anyWordV
  opsize <- instrOperandSize
  rn <- registerName (fromIntegral reg)
  return $ Instr MOV opsize [OpReg rn (fromIntegral reg), 
			     OpImm (fromIntegral imm)]

parseRETN 0xc2 = do
    w <- anyWord16
    return $ Instr RET OPNONE [OpImm (fromIntegral w)]
parseRETN 0xc3 = return $ Instr RET OPNONE []

parseLoadSegmentRegister opcode b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  return $ Instr opcode OPNONE [op2, op1]

parseENTER b = do
    w <- anyWord16
    b <- anyWord8
    return $ Instr ENTER OPNONE [OpImm (fromIntegral w), 
       		           OpImm (fromIntegral b)]

-- Floating-point operations.  These can probably shortened by doing some
-- arithmetic/logical tricks on the opcodes, but since the instruction
-- set is still quite irregular (even though much better than the integer
-- ops), I haven't bothered yet.

parseESC 0xd8 = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1, op2, mod, reg, rm) <- parseAddress32' OPF32 modrm
             return $ Instr (ops !! fromIntegral reg) OPF32 [op1]
     else if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg 0, OpFPReg (fromIntegral (modrm .&. 0x0f))]
              else return $ Instr 
       	     (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg 0, OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8))]
 where ops = [FADD, FMUL, FCOM, FCOMP, 
               FSUB, FSUBR, FDIV, FDIVR]
             
parseESC b@0xd9 = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1', op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
	     let op1 = case op1' of 
		         OpAddr a _ -> OpAddr a  (opsizes !! fromIntegral reg)
			 op -> op
             return $ Instr (lowOps !! fromIntegral reg) 
       	              (opsizes !! fromIntegral reg) [op1]
     else if (modrm < 0xd0)
             then if (modrm .&. 0x0f) < 8
                    then return $ Instr 
       	          (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                         [OpFPReg 0, OpFPReg (fromIntegral (modrm .&. 0x0f))]
                    else return $ Instr 
       	          (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                         [OpFPReg 0, OpFPReg (fromIntegral (modrm .&. 0x0f)
       			      - 8)]
              else case modrm of
       		     0xd0 -> return $ Instr FNOP OPNONE []
                     0xe0 -> return $ Instr FCHS OPNONE []
                     0xe1 -> return $ Instr FABS OPNONE []
                     0xe4 -> return $ Instr FTST OPNONE []
                     0xe5 -> return $ Instr FXAM OPNONE []
                     0xe8 -> return $ Instr FLD1 OPNONE []
                     0xe9 -> return $ Instr FLDL2T OPNONE []
                     0xea -> return $ Instr FLDL2E OPNONE []
                     0xeb -> return $ Instr FLDPI OPNONE []
                     0xec -> return $ Instr FLDLG2 OPNONE []
                     0xed -> return $ Instr FLDLN2 OPNONE []
                     0xee -> return $ Instr FLDZ OPNONE []
                     _ -> parseInvalidOpcode b
 where lowOps = [FLD, InvalidOpcode, FST, FSTP, 
                  FLDENV, FLDCW, FSTENV, FSTCW]
       opsizes = [OPF32, OPNONE, OPF32, OPF32,
                   OPNONE, OPNONE, OPNONE, OPNONE]
       ops = [FLD, FXCH]

parseESC 0xda = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1, op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
             return $ Instr (ops !! fromIntegral reg) OPNONE [op1]
     else if (modrm < 0xe0)
             then return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg 0, OpFPReg (fromIntegral (modrm .&. 0x0f))]
              else case modrm of
                     0xe1 -> return $ Instr FUCOMPP OPNONE []
                     _ -> parseInvalidOpcode 0xda
 where ops = [FIADD, FIMUL, FICOM, FICOMP, 
               FISUB, FISUBR, FIDIV, FIDIVR]
       ops' = [FCMOVB, FCMOVE, FCMOVBE, FCMOVU]

parseESC 0xdb = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1', op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
	     let op1 = case op1' of 
		         OpAddr a _ -> OpAddr a  (opsizes !! fromIntegral reg)
			 op -> op
             return $ Instr (ops !! fromIntegral reg) 
       	              (opsizes !! fromIntegral reg) [op1]
     else 
      case modrm of
         0xe2 -> return $ Instr FCLEX OPNONE []
         0xe3 -> return $ Instr FINIT OPNONE []
         _ ->
           if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg 0, OpFPReg (fromIntegral (modrm .&. 0x0f))]
              else return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg 0, OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8))]
 where ops = [FILD, FISTP, FIST, FISTP, 
               InvalidOpcode, FLD, InvalidOpcode, FSTP]
       opsizes = [OP32, OP32, OP32, OP32,
                   OPNONE, OPF80, OPNONE, OPF80]
       ops' = [FCMOVNB, FCMOVNE, FCMOVNBE, FCMOVNU,
                InvalidOpcode, FUCOMI, FCOMI, InvalidOpcode]

parseESC 0xdc = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1, op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
             return $ Instr (ops !! fromIntegral reg) OPNONE [op1]
     else
       if modrm >= 0xd0 && modrm < 0xe0
        then parseInvalidOpcode 0xdc
        else if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral (modrm .&. 0x0f)), OpFPReg 0]
              else return $ Instr 
       	     (ops !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8)), OpFPReg 0]
 where ops = [FADD, FMUL, FCOM, FCOMP, 
               FSUB, FSUBR, FDIV, FDIVR]
             
parseESC 0xdd = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1', op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
	     let op1 = case op1' of 
		         OpAddr a _ -> OpAddr a  (opsizes !! fromIntegral reg)
			 op -> op
             return $ Instr (ops !! fromIntegral reg) 
       	              (opsizes !! fromIntegral reg) [op1]
     else
       if (modrm >= 0xc8) && modrm <= 0xd0 || (modrm >= 0xf0 && modrm < 0xff)
        then parseInvalidOpcode 0xdc
        else if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral (modrm .&. 0x0f)), OpFPReg 0]
              else return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8)), OpFPReg 0]
 where ops = [FLD, FISTTP, FST, FSTP, 
               FRSTOR, InvalidOpcode, FSAVE, FSTSW]
       opsizes = [OPF64, OP64, OPF64, OPF64,
                   OPNONE, OPNONE, OPNONE, OP16]
       ops' = [FFREE, InvalidOpcode, FST, FSTP, 
                FUCOM, FUCOMP]
             
parseESC 0xde = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1, op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
             return $ Instr (ops !! fromIntegral reg) OPNONE [op1]
     else
       if modrm >= 0xd0 && modrm <= 0xe0
        then case modrm of
       	 0xd9 -> return $ Instr FCOMPP OPNONE []
       	 _ -> parseInvalidOpcode 0xde
        else if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral (modrm .&. 0x0f)), OpFPReg 0]
              else return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8)), OpFPReg 0]
 where ops = [FIADD, FIMUL, FICOM, FICOMP, 
               FISUB, FISUBR, FIDIV, FIDIVR]
       ops' = [FADDP, FMULP, InvalidOpcode, InvalidOpcode,
                FSUBRP, FSUBP, FDIVRP, FDIVP]
             
             
parseESC 0xdf = do
  modrm <- anyWord8
  let modrm' :: Word8
      modrm' = modrm - 0xc0
  if modrm <= 0xbf
     then do (op1, op2, mod, reg, rm) <- parseAddress32' OPNONE modrm
             return $ Instr (ops !! fromIntegral reg) OPNONE [op1]
     else
       case modrm of
           0xe0 -> return $ Instr FSTSW OPNONE [OpReg "ax" 0]
           _ -> 
             if (modrm >= 0xe8 && modrm <= 0xef) ||
                (modrm >= 0xf0 && modrm <= 0xf7)
             then
             if (modrm .&. 0x0f) < 0x8
             then return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral (modrm .&. 0x0f)), OpFPReg 0]
              else return $ Instr 
       	     (ops' !! fromIntegral ((modrm' `shiftR` 3))) OPNONE
                    [OpFPReg (fromIntegral ((modrm .&. 0x0f) - 8)), OpFPReg 0]
             else parseInvalidOpcode 0xdf
 where ops = [FILD, FISTPP, FIST, FISTP, 
               FBLD, FILD, FBSTP, FISTP]
       ops' = [InvalidOpcode, InvalidOpcode, InvalidOpcode, InvalidOpcode,
                InvalidOpcode, FUCOMIP, FCOMIP, InvalidOpcode]

parseINImm 0xe4 = do
    b <- anyWord8
    return $ Instr IN OP8 [OpReg "al" 0, OpImm (fromIntegral b)]
parseINImm 0xe5 = do
    b <- anyWord8
    rn <- registerName 0
    opsize <- instrOperandSize
    return $ Instr IN opsize [OpReg rn 0, OpImm (fromIntegral b)]
parseOUTImm 0xe6 = do
    b <- anyWord8
    return $ Instr OUT OP8 [OpImm (fromIntegral b), OpReg "al" 0]
parseOUTImm 0xe7 = do
    b <- anyWord8
    rn <- registerName 0
    opsize <- instrOperandSize
    return $ Instr OUT opsize [OpImm (fromIntegral b), OpReg rn 0]

parseIN 0xec = do
    return $ Instr IN OP8 [OpReg "al" 0, OpReg "dx" 2]
parseIN 0xed = do
    rn <- registerName 0
    opsize <- instrOperandSize
    return $ Instr IN opsize [OpReg rn 0, OpReg "dx" 2]
parseOUT 0xee = do
    return $ Instr OUT OP8 [OpReg "dx" 2, OpReg "al" 0]
parseOUT 0xef = do
    rn <- registerName 0
    opsize <- instrOperandSize
    return $ Instr OUT opsize [OpReg "dx" 2, OpReg rn 0]

-- Return the name of the register encoded with R.  Take 64-bit mode and
-- possible REX and operand-size prefixes into account.

registerName r = do
    st <- getState
    if in64BitMode st && hasREX rex_R st
       then return $ "r" ++ show (r + 8)
       else case operandBitMode st of
              BIT16 -> return $ regnames16 !! r
              BIT32 -> return $ regnames32 !! r

instrOperandSize = do
    st <- getState
    if in64BitMode st && hasREX rex_W st
       then return $ OP64
       else case operandBitMode st of
              BIT16 -> return OP16
              BIT32 -> return OP32

regnames8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
regnames16 = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
regnames32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
regnames64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"]
segregnames = ["es", "cs", "ss", "ds", "fs", "gs", "<invalid>", "<invalid>"]
mmxregs = ["mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"]
xmmregs = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"]

jccname 0 = JO
jccname 1 = JNO
jccname 2 = JB
jccname 3 = JNB
jccname 4 = JE
jccname 5 = JNE
jccname 6 = JBE
jccname 7 = JA
jccname 8 = JS
jccname 9 = JNS
jccname 10 = JP
jccname 11 = JNP
jccname 12 = JL
jccname 13 = JGE
jccname 14 = JLE
jccname 15 = JG

setccname 0 = SETO
setccname 1 = SETNO
setccname 2 = SETB
setccname 3 = SETNB
setccname 4 = SETE
setccname 5 = SETNE
setccname 6 = SETBE
setccname 7 = SETA
setccname 8 = SETS
setccname 9 = SETNS
setccname 10 = SETP
setccname 11 = SETNP
setccname 12 = SETL
setccname 13 = SETGE
setccname 14 = SETLE
setccname 15 = SETG

cmovccname 0 = CMOVO
cmovccname 1 = CMOVNO
cmovccname 2 = CMOVB
cmovccname 3 = CMOVNB
cmovccname 4 = CMOVE
cmovccname 5 = CMOVNE
cmovccname 6 = CMOVBE
cmovccname 7 = CMOVA
cmovccname 8 = CMOVS
cmovccname 9 = CMOVNS
cmovccname 10 = CMOVP
cmovccname 11 = CMOVNP
cmovccname 12 = CMOVL
cmovccname 13 = CMOVGE
cmovccname 14 = CMOVLE
cmovccname 15 = CMOVG

parseGrp1 0x80 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  immb <- anyWord8
  return $ Instr (aluOps !! fromIntegral reg) OP8 
    [op1, OpImm (fromIntegral immb)]
parseGrp1 0x81 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  immb <- anyWordZ
  return $ Instr (aluOps !! fromIntegral reg) opsize 
    [op1, OpImm (fromIntegral immb)]
parseGrp1 0x82 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  immb <- anyWord8
  return $ Instr (aluOps !! fromIntegral reg) OP8 
    [op1, OpImm (fromIntegral immb)]
parseGrp1 0x83 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  immb <- anyWord8
  return $ Instr (aluOps !! fromIntegral reg) opsize
    [op1, OpImm (fromIntegral immb)]
aluOps = [ADD, OR, ADC, SBB, AND, SUB, XOR, CMP]


parseGrp1A b = do
   opsize <- instrOperandSize
   (op1, op2, mod, reg, rm) <- parseAddress32 opsize
   case reg of
     0 -> return $ Instr POP opsize [op1]
     _ -> parseInvalidOpcode b

parseGrp2 0xc0 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  immb <- anyWord8
  return $ Instr (shiftOps !! fromIntegral reg) OP8 
      [op1, OpImm (fromIntegral immb)]
parseGrp2 0xc1 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  imm <- anyWord8
  return $ Instr (shiftOps !! fromIntegral reg) opsize
      [op1, OpImm (fromIntegral imm)]
parseGrp2 0xd0 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr (shiftOps !! fromIntegral reg) OP8 [op1, OpImm 1]
parseGrp2 0xd1 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr (shiftOps !! fromIntegral reg) opsize [op1, OpImm 1]
parseGrp2 0xd2 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  return $ Instr (shiftOps !! fromIntegral reg) OP8 [op1, OpReg "cl" 1]
parseGrp2 0xd3 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr (shiftOps !! fromIntegral reg) opsize [op1, OpReg "cl" 1]
shiftOps = [ROL, ROR, RCL, RCR, SHL, SHR, InvalidOpcode, SAR]

parseGrp3 0xf6 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  case reg of
    0 -> do imm <- anyWord8
            return $ Instr TEST OP8 [op1, OpImm (fromIntegral imm)]
    1 -> parseInvalidOpcode 0xf6
    2 -> return $ Instr NOT OP8 [op1]
    3 -> return $ Instr NEG OP8 [op1]
    4 -> return $ Instr MUL OP8 [OpReg "al" 0, op1]
    5 -> return $ Instr IMUL OP8 [OpReg "al" 0, op1]
    6 -> return $ Instr DIV OP8 [OpReg "al" 0, op1]
    7 -> return $ Instr IDIV OP8 [OpReg "al" 0, op1]
parseGrp3 0xf7 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  rn <- registerName 0
  case reg of
    0 -> do imm <- anyWordZ
            return $ Instr TEST opsize [op1, OpImm (fromIntegral imm)]
    1 -> parseInvalidOpcode 0xf6
    2 -> return $ Instr NOT opsize [op1]
    3 -> return $ Instr NEG opsize [op1]
    4 -> return $ Instr MUL opsize [OpReg rn 0, op1]
    5 -> return $ Instr IMUL opsize [OpReg rn 0, op1]
    6 -> return $ Instr DIV opsize [OpReg rn 0, op1]
    7 -> return $ Instr IDIV opsize [OpReg rn 0, op1]

parseGrp4 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  case reg of
    0 -> return $ Instr INC OP8 [op1]
    1 -> return $ Instr DEC OP8 [op1]
    _ -> parseInvalidOpcode b

parseGrp5 b = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  case reg of
    0 -> return $ Instr INC opsize [op1]
    1 -> return $ Instr DEC opsize [op1]
    2 -> return $ Instr CALL OPNONE [op1]
    3 -> do w <- anyWord16
            return $ Instr CALLF OPNONE [OpAddr (fromIntegral w) OPNONE, op1]
    4 -> return $ Instr JMPN OPNONE [op1]
    5 -> do w <- anyWord16
            return $ Instr JMPF OPNONE [OpAddr (fromIntegral w) OPNONE, op1]
    6 -> return $ Instr PUSH opsize [op1]
    _ -> parseInvalidOpcode b

parseGrp6 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  case reg of
    0 -> return $ Instr SLDT OPNONE [op1]
    1 -> return $ Instr STR OPNONE [op1]
    2 -> return $ Instr LLDT OPNONE [op1]
    3 -> return $ Instr LTR OPNONE [op1]
    4 -> return $ Instr VERR OPNONE [op1]
    5 -> return $ Instr VERW OPNONE [op1]
    _ -> parseInvalidOpcode b

parseGrp7 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  case mod of
    3 -> case reg of
           0 -> case rm of
       		  1 -> return $ Instr VMCALL OPNONE []
       		  2 -> return $ Instr VMLAUNCH OPNONE []
       		  3 -> return $ Instr VMRESUME OPNONE []
       		  4 -> return $ Instr VMXOFF OPNONE []
       		  _ -> parseInvalidOpcode b
           1 -> case rm of
       		  0 -> return $ Instr MONITOR OPNONE []
       		  1 -> return $ Instr MWAIT OPNONE []
       		  _ -> parseInvalidOpcode b
           4 -> return $ Instr SMSW OPNONE [op1]
           6 -> return $ Instr LMSW OPNONE [op1]
           7 -> case rm of
       		  0 -> onlyIn64BitMode
       	                 (\b -> return $ Instr SWAPGS OPNONE []) b
       		  _ -> parseInvalidOpcode b
           _ -> parseInvalidOpcode b
    _ -> case reg of
           0 -> return $ Instr SGDT OPNONE [op1]
           1 -> return $ Instr SIDT OPNONE [op1]
           2 -> return $ Instr LGDT OPNONE [op1]
           3 -> return $ Instr LIDT OPNONE [op1]
           4 -> return $ Instr SMSW OPNONE [op1]
           5 -> parseInvalidOpcode b
           6 -> return $ Instr LMSW OPNONE [op1]
           7 -> return $ Instr INVLPG OPNONE [op1]

parseGrp8 b = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  imm <- anyWord8
  case reg of
    4 -> return $ Instr BT opsize [op1, OpImm (fromIntegral imm)]
    5 -> return $ Instr BTS opsize [op1, OpImm (fromIntegral imm)]
    6 -> return $ Instr BTR opsize [op1, OpImm (fromIntegral imm)]
    7 -> return $ Instr BTC opsize [op1, OpImm (fromIntegral imm)]
    _ -> parseInvalidOpcode b

parseGrp9 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  st <- getState
  case mod of
    3 -> parseInvalidOpcode b
    _ -> case reg of
            1 -> if hasREX rex_W st
                    then return $ Instr CMPXCHG16B OPNONE [op1]
                    else return $ Instr CMPXCHG8B OPNONE [op1]
            6 -> if hasPrefix 0x66 st
                   then return $ Instr VMCLEAR OPNONE [op1]
       	     else if hasPrefix 0xf3 st
       	          then return $ Instr VMXON OPNONE [op1]
       	          else return $ Instr VMPTRLD OPNONE [op1]
            7 -> return $ Instr VMPTRST OPNONE [op1]
            _ -> parseInvalidOpcode b

parseGrp10 = parseInvalidOpcode

parseGrp11 0xc6 = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  imm <- anyWord8
  return $ Instr MOV OP8 [op1, OpImm (fromIntegral imm)]
parseGrp11 0xc7 = do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  imm <- anyWordZ
  return $ Instr MOV opsize [op1, OpImm (fromIntegral imm)]

mmxInstr op1 mod reg rm name = do
  st <- getState
  imm <- anyWord8
  if hasPrefix 0x66 st
     then return $ Instr name OP128
           [OpReg (xmmregs !! fromIntegral rm) (fromIntegral rm),
	    OpImm (fromIntegral imm)]
     else return $ Instr name OP64
           [OpReg (mmxregs !! fromIntegral rm) (fromIntegral rm),
	    OpImm (fromIntegral imm)]
       	
parseGrp12 b = do
  st <- getState
  let opsize = if hasPrefix 0x66 st then OP128 else OP64
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  case mod of
    3 -> case reg of
           2 -> mmxInstr op1 mod reg rm PSRLW
           4 -> mmxInstr op1 mod reg rm PSRAW
           6 -> mmxInstr op1 mod reg rm PSLLW
           _ -> parseInvalidOpcode b
    _ -> parseInvalidOpcode b
parseGrp13 b = do
  st <- getState
  let opsize = if hasPrefix 0x66 st then OP128 else OP64
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  case mod of
    3 -> case reg of
           2 -> mmxInstr op1 mod reg rm PSRLD
           4 -> mmxInstr op1 mod reg rm PSRAD
           6 -> mmxInstr op1 mod reg rm PSLLD
           _ -> parseInvalidOpcode b
    _ -> parseInvalidOpcode b
parseGrp14 b = do
  st <- getState
  let opsize = if hasPrefix 0x66 st then OP128 else OP64
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  st <- getState
  case mod of
    3 -> case reg of
           2 -> mmxInstr op1 mod reg rm PSRLQ
           3 -> if hasPrefix 0x66 st
		   then mmxInstr op1 mod reg rm PSRLDQ
       		   else parseInvalidOpcode b
           6 -> mmxInstr op1 mod reg rm PSLLQ
           7 -> if hasPrefix 0x66 st
                   then mmxInstr op1 mod reg rm PSLLDQ
       	           else parseInvalidOpcode b
	   _ -> parseInvalidOpcode b
    _ -> parseInvalidOpcode b

parseGrp15 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  case mod of
    3 -> case reg of
            5 -> return $ Instr LFENCE OPNONE []
            6 -> return $ Instr MFENCE OPNONE []
            7 -> return $ Instr SFENCE OPNONE []
            _ -> parseInvalidOpcode b
    _ -> case reg of
            0 -> return $ Instr FXSAVE OPNONE [op1]
            1 -> return $ Instr FXRSTOR OPNONE [op1]
            2 -> return $ Instr LDMXCSR OPNONE [op1]
            3 -> return $ Instr STMXCSR OPNONE [op1]
            7 -> return $ Instr CLFLUSH OPNONE [op1]
            _ -> parseInvalidOpcode b
parseGrp16 b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OPNONE
  case mod of
    3 -> parseInvalidOpcode b
    _ -> case reg of
            0 -> return $ Instr PREFETCHNTA OPNONE [op1]
            1 -> return $ Instr PREFETCHT0 OPNONE [op1]
            2 -> return $ Instr PREFETCHT1 OPNONE [op1]
            3 -> return $ Instr PREFETCHT2 OPNONE [op1]
            _ -> parseInvalidOpcode b

parseXmmVW p p0xf3 p0x66 p0xf2 b =
    do (op1, op2, mod, reg, rm) <- parseAddress32 OP128
       st <- getState
       let v = OpReg (xmmregs !! (fromIntegral reg)) (fromIntegral reg)
       let w = case op1 of
	         OpReg _ num -> OpReg (xmmregs !! num) num
		 op -> op
       if hasPrefix 0xf3 st
	  then return $ Instr p0xf3 OP128 [v, w]
	  else if hasPrefix 0x66 st
	          then return $ Instr p0x66 OP128 [v, w]
		  else if hasPrefix 0xf2 st
		          then return $ Instr p0xf2 OP128 [v, w]
			  else return $ Instr p OP128 [v, w]
parseXmmWV p p0xf3 p0x66 p0xf2 b =
    do (op1, op2, mod, reg, rm) <- parseAddress32 OP128
       st <- getState
       let w = OpReg (xmmregs !! (fromIntegral reg)) (fromIntegral reg)
       let v = case op1 of
	         OpReg _ num -> OpReg (xmmregs !! num) num
		 op -> op
       if hasPrefix 0xf3 st
	  then return $ Instr p0xf3 OP128 [v, w]
	  else if hasPrefix 0x66 st
	          then return $ Instr p0x66 OP128 [v, w]
		  else if hasPrefix 0xf2 st
		          then return $ Instr p0xf2 OP128 [v, w]
			  else return $ Instr p OP128 [v, w]

parseXmmGU p p0xf3 p0x66 p0xf2 b =
    do (mod, reg, rm) <- parseModRM
       st <- getState
       let g = OpReg (regnames32 !! (fromIntegral reg)) (fromIntegral reg)
       let u = OpReg (xmmregs !! (fromIntegral rm)) (fromIntegral rm)
       if hasPrefix 0xf3 st
	  then return $ Instr p0xf3 OP32 [g, u]
	  else if hasPrefix 0x66 st
	          then return $ Instr p0x66 OP32 [g, u]
		  else if hasPrefix 0xf2 st
		          then return $ Instr p0xf2 OP32 [g, u]
			  else return $ Instr p OP32 [g, u]

parseMOVUPS b@0x10 = parseXmmVW MOVUPS MOVSS MOVUPD MOVSD b
parseMOVUPS b@0x11 = parseXmmWV MOVUPS MOVSS MOVUPD MOVSD b
parseMOVLPS b@0x12 = parseXmmWV MOVLPS MOVSLDUP MOVLPD MOVDDUP b
parseMOVLPS b@0x13 = parseXmmVW MOVLPS InvalidOpcode MOVLPD InvalidOpcode b
parseUNPCKLPS b@0x14 =
    parseXmmVW UNPCKLPS InvalidOpcode UNPCKLPD InvalidOpcode b
parseUNPCKHPS b@0x15 = 
    parseXmmVW UNPCKHPS InvalidOpcode UNPCKHPD InvalidOpcode b
parseMOVHPS b@0x16 = parseXmmVW MOVHPS MOVLSDUP MOVHPD MOVLHPS b
parseMOVHPS b@0x17 = parseXmmVW MOVHPS InvalidOpcode MOVHPD InvalidOpcode b

parseMOVCtrlDebug 0x20 = 
    do (mod, reg, rm) <- parseModRM
       return $ Instr MOV OPNONE [OpReg (regnames32 !! fromIntegral rm)
				  (fromIntegral rm),
				  OpReg ("cr" ++ show reg) (fromIntegral reg)]
parseMOVCtrlDebug 0x21 = 
    do (mod, reg, rm) <- parseModRM
       return $ Instr MOV OPNONE [OpReg (regnames32 !! fromIntegral rm)
				  (fromIntegral rm),
				  OpReg ("db" ++ show reg) (fromIntegral reg)]
parseMOVCtrlDebug 0x22 = 
    do (mod, reg, rm) <- parseModRM
       return $ Instr MOV OPNONE [OpReg ("cr" ++ show reg) (fromIntegral reg),
				  OpReg (regnames32 !! fromIntegral rm)
				  (fromIntegral rm)]
parseMOVCtrlDebug 0x23 = 
    do (mod, reg, rm) <- parseModRM
       return $ Instr MOV OPNONE [OpReg ("db" ++ show reg) (fromIntegral reg),
				  OpReg (regnames32 !! fromIntegral rm)
				  (fromIntegral rm)]
  

parseMOVAPS b@0x28 = parseXmmVW MOVAPS InvalidOpcode MOVAPD InvalidOpcode b
parseMOVAPS b@0x29 = parseXmmWV MOVAPS InvalidOpcode MOVAPD InvalidOpcode b
parseCVTI2PS = parseUnimplemented
parseMOVNTPS = parseXmmWV MOVNTPS InvalidOpcode MOVNTPD InvalidOpcode
parseCVTPS2PI = parseUnimplemented
parseCVTTPS2PI = parseUnimplemented
parseUCOMISS = parseXmmVW UCOMISS InvalidOpcode UCOMISD InvalidOpcode
parseCOMISS = parseXmmVW COMISS InvalidOpcode COMISD InvalidOpcode

parseCMOVcc b= do
  opsize <- instrOperandSize
  (op1, op2, mod, reg, rm) <- parseAddress32 opsize
  return $ Instr (cmovccname (b .&. 0xf)) OPNONE [op2, op1]
  
parseMOVSKPS = parseXmmGU MOVMSKPS InvalidOpcode MOVMSKPD InvalidOpcode

parseSQRTPS = parseXmmVW SQRTPS SQRTSS SQRTPD SQRTSD
parseRSQRTPS = parseXmmVW RSQRTPS RSQRTSS InvalidOpcode InvalidOpcode
parseRCPPS = parseXmmVW RCPPS RCPSS InvalidOpcode InvalidOpcode
parseCVTPS2PD = parseUnimplemented
parseANDNPS = parseXmmVW ANDNPS InvalidOpcode ANDNPD InvalidOpcode
parseANDPS =  parseXmmVW ANDPS InvalidOpcode ANDPD InvalidOpcode
parseORPS = parseXmmVW ORPS InvalidOpcode ORPD InvalidOpcode
parseXORPS = parseXmmVW XORPS InvalidOpcode XORPD InvalidOpcode
parseADDPS = parseXmmVW ADDPS ADDSS ADDPD ADDSD
parseMULPS = parseXmmVW MULPS MULSS MULPD MULSD
parseCVTDQ2PS = parseUnimplemented
parsePUNPCKLWD = parseUnimplemented
parsePACKSSWB = parseUnimplemented
parsePUNPCKHWD = parseUnimplemented
parseSUBPS = parseXmmVW SUBPS SUBSS SUBPD SUBSD
parseMINPS = parseXmmVW MINPS MINSS MINPD MINSD
parseDIVPS = parseXmmVW DIVPS DIVSS DIVPD DIVSD
parseMAXPS = parseXmmVW MAXPS MAXSS MAXPD MAXSD
parsePUNPCKLBW = parseUnimplemented
parsePUNPCKLDQ = parseUnimplemented
parsePACKUSWB = parseUnimplemented
parsePCMPGTB = parseUnimplemented
parsePCMPGTW = parseUnimplemented
parsePCMPGTD = parseUnimplemented
parsePUNPCKHBW = parseUnimplemented
parsePUNPCKHDQ = parseUnimplemented
parsePACKSSDW = parseUnimplemented
parsePUNPCKLQDQ = parseUnimplemented
parsePUNPCKHQDQ = parseUnimplemented
parsePSHUFW = parseUnimplemented
parsePCMPEQB = parseUnimplemented
parsePCMPEQW = parseUnimplemented
parsePCMPEQD = parseUnimplemented

parseVMREAD b = 
    do st <- getState
       if in64BitMode st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  return $ Instr VMREAD OP64 [op1, op2]
	  else do (op1, op2, mod, reg, rm) <- parseAddress32 OP32
		  return $ Instr VMREAD OP32 [op1, op2]
parseVMWRITE b = 
    do st <- getState
       if in64BitMode st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  return $ Instr VMWRITE OP64 [op1, op2]
	  else do (op1, op2, mod, reg, rm) <- parseAddress32 OP32
		  return $ Instr VMWRITE OP32 [op1, op2]

parseHADDPS = parseXmmVW InvalidOpcode InvalidOpcode HADDPD HADDPS
parseHSUBPS = parseXmmVW InvalidOpcode InvalidOpcode HSUBPS HSUBPD

parseMOVD_Q = parseUnimplemented

parseJccLong b = do
  disp <- anyIntZ
  let disp' :: Int
      disp' = fromIntegral disp
  pos <- getPosition
  st <- getState
  return $ Instr (jccname (b .&. 0xf)) OPNONE
        [OpAddr (fromIntegral (disp' + sourceColumn pos - 1) +
                (startAddr st)) OPNONE]

parseSETcc b = do
  (op1, op2, mod, reg, rm) <- parseAddress32 OP8
  case op1 of
    OpReg name num -> return $ Instr (setccname (b .&. 0xf)) OPNONE 
		      [OpReg (regnames8 !! fromIntegral num) num]
    _ -> return $ Instr (setccname (b .&. 0xf)) OPNONE [op1]

parseSHLD 0xa4 = 
    do opsize <- instrOperandSize
       (op1, op2, mod, reg, rm) <- parseAddress32 opsize
       b <- anyWord8
       opsize <- instrOperandSize
       return $ Instr SHLD opsize [op1, op2, OpImm (fromIntegral b)]
parseSHLD 0xa5 = 
    do opsize <- instrOperandSize
       (op1, op2, mod, reg, rm) <- parseAddress32 opsize
       opsize <- instrOperandSize
       return $ Instr SHLD opsize [op1, op2, OpReg "cl" 1]
parseSHRD 0xac = 
    do opsize <- instrOperandSize
       (op1, op2, mod, reg, rm) <- parseAddress32 opsize
       b <- anyWord8
       opsize <- instrOperandSize
       return $ Instr SHRD opsize [op1, op2, OpImm (fromIntegral b)]
parseSHRD 0xad = 
    do opsize <- instrOperandSize
       (op1, op2, mod, reg, rm) <- parseAddress32 opsize
       opsize <- instrOperandSize
       return $ Instr SHRD opsize [op1, op2, OpReg "cl" 1]

parseCMPPS = parseUnimplemented
parseMOVNTI = parseUnimplemented
parsePINSRW = parseUnimplemented
parsePEXTRW = parseUnimplemented
parseSHUFPS = parseUnimplemented

parseBSWAP b = 
    do let reg = (b .&. 0xf) - 8
       r <- registerName (fromIntegral reg)
       opsize <- instrOperandSize
       return $ Instr BSWAP opsize [OpReg r (fromIntegral reg)]

parseADDSUBPS = parseXmmVW InvalidOpcode InvalidOpcode ADDSUBPD ADDUBPS

parseMmxXmmPQVW opcode b =
    do st <- getState
       if hasPrefix 0x66 st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP128
		  let v = OpReg (xmmregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  let w = case op1 of
			    OpReg _ num -> OpReg (xmmregs !! num) num
			    op -> op
		  return $ Instr opcode OP128 [v, w]
	  else do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  let p = OpReg (mmxregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  let q = case op1 of
			    OpReg _ num -> OpReg (mmxregs !! num) num
			    op -> op
		  return $ Instr opcode OP128 [p, q]

parseMmxXmmMPMV opcode1 opcode2 b =
    do st <- getState
       if hasPrefix 0x66 st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP128
		  let v = OpReg (xmmregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  return $ Instr opcode2 OP128 [op1, v]
	  else do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  let p = OpReg (mmxregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  return $ Instr opcode1 OP128 [op1, p]

parseMmxXmmPNVU opcode b =
    do st <- getState
       if hasPrefix 0x66 st
	  then do (mod, reg, rm) <- parseModRM
		  let v = OpReg (xmmregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  let u = OpReg (xmmregs !! (fromIntegral rm))
			  (fromIntegral reg)
		  return $ Instr opcode OP128 [v, u]
	  else do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  let p = OpReg (mmxregs !! (fromIntegral reg)) 
			  (fromIntegral reg)
		  let n = OpReg (mmxregs !! (fromIntegral rm))
			  (fromIntegral reg)
		  return $ Instr opcode OP128 [p, n]

parsePSRLW = parseMmxXmmPQVW PSRLW
parsePSRLD = parseMmxXmmPQVW PSRLD
parsePSRLQ = parseMmxXmmPQVW PSRLQ
parsePADDQ = parseMmxXmmPQVW PADDQ
parsePMULLW = parseMmxXmmPQVW PMULLW
parseMOVQ b@0x6f = parseUnimplemented b
parseMOVQ b@0x7f = parseUnimplemented b
parseMOVQ b@0xd6 = 
    do st <- getState
       if hasPrefix 0x66 st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP64
		  return $ Instr MOVQ OP64 [op1, op2]
	  else if hasPrefix 0xf3 st
	          then do (mod, reg, rm) <- parseModRM
			  return $ Instr MOVQ OPNONE 
				     [OpReg (xmmregs !! (fromIntegral reg))
				      (fromIntegral reg),
				      OpReg (mmxregs !! (fromIntegral rm))
				      (fromIntegral rm)]
		  else
		    if hasPrefix 0xf2 st
		       then do (mod, reg, rm) <- parseModRM
			       return $ Instr MOVQ OPNONE
				[OpReg (mmxregs !! (fromIntegral reg))
				 (fromIntegral reg),
				 OpReg (xmmregs !! (fromIntegral rm))
				 (fromIntegral rm)]
		       else parseInvalidOpcode b
			  
parsePMOVMSKB b = 
    do st <- getState
       (mod, reg, rm) <- parseModRM
       if hasPrefix 0x66 st
	  then do return $ Instr PMOVMSKB OPNONE 
			     [OpReg (regnames32 !! (fromIntegral reg))
			      (fromIntegral reg),
			      OpReg (xmmregs !! (fromIntegral rm))
			      (fromIntegral rm)]
	  else do return $ Instr PMOVMSKB OPNONE 
			     [OpReg (regnames32 !! (fromIntegral reg))
			      (fromIntegral reg),
			      OpReg (mmxregs !! (fromIntegral rm))
			      (fromIntegral rm)]
parsePSUBUSB = parseMmxXmmPQVW PSUBUSB
parsePSUBUSW = parseMmxXmmPQVW PSUBUSW
parsePMINUB = parseMmxXmmPQVW PMINUB
parsePAND = parseMmxXmmPQVW PAND
parsePADDUSB = parseMmxXmmPQVW PADDUSB
parsePADDUSW = parseMmxXmmPQVW PADDUSW
parsePMAXUB = parseMmxXmmPQVW PMAXUB
parsePANDN = parseMmxXmmPQVW PANDN
parsePAVGB = parseMmxXmmPQVW PAVGB
parsePSRAW = parseMmxXmmPQVW PSRAW
parsePSRAD = parseMmxXmmPQVW PSRAD
parsePAVGW = parseMmxXmmPQVW PAVGW
parseCVTPD2DQ = parseUnimplemented
parsePMULHUW = parseMmxXmmPQVW PMULHUW
parsePMULHW = parseMmxXmmPQVW PMULHW
parseMOVNTQ = parseMmxXmmMPMV MOVNTQ MOVNTDQ
parsePSUBSB = parseMmxXmmPQVW PSUBSB
parsePSUBSQ = parseMmxXmmPQVW PSUBSQ
parsePMINSW = parseMmxXmmPQVW PMINSW
parsePOR = parseMmxXmmPQVW POR
parsePADDSB = parseMmxXmmPQVW PADDSB
parsePADDSW = parseMmxXmmPQVW PADDSW
parsePMAXSW = parseMmxXmmPQVW PMAXSW
parsePXOR = parseMmxXmmPQVW PXOR
parseLDDQU b = 
    do st <- getState
       if hasPrefix 0xf2 st
	  then do (op1, op2, mod, reg, rm) <- parseAddress32 OP128
		  let v = OpReg (xmmregs !! (fromIntegral reg))
		          (fromIntegral reg)
		  return $ Instr LDDQU OP128 [v, op1]
	  else parseInvalidOpcode b
parsePSLLW = parseMmxXmmPQVW PSLLW
parsePSLLD = parseMmxXmmPQVW PSLLD
parsePSLLQ = parseMmxXmmPQVW PSLLQ
parsePMULUDQ = parseMmxXmmPQVW PMULUDQ
parsePMADDWD = parseMmxXmmPQVW PMADDWD
parsePSADBW = parseMmxXmmPQVW PSADBW
parseMASKMOVQ = parseMmxXmmPNVU MASKMOVQ
parsePSUBB = parseMmxXmmPQVW PSUBB
parsePSUBW = parseMmxXmmPQVW PSUBW
parsePSUBD = parseMmxXmmPQVW PSUBD
parsePSUBQ = parseMmxXmmPQVW PSUBQ
parsePADDB = parseMmxXmmPQVW PADDB
parsePADDW = parseMmxXmmPQVW PADDW
parsePADDD = parseMmxXmmPQVW PADDD

package io.joern.ghidra2cpg.processors
import scala.collection.immutable._

class Mips extends Processor {
  override def getInstructions: HashMap[String, String] =
    HashMap(
      "_addiu" -> "<operator>.assignment",
      "_addu"  -> "<operator>.assignment",
      "_and"   -> "<operator>.and",
      "_li"    -> "<operator>.assignment",
      "_lui"   -> "<operator>.assignment",
      "_lw"    -> "<operator>.assignment",
      "_nop"   -> "<operator>.NOP",
      "_or"    -> "<operator>.or",
      "_sw"    -> "<operator>.assignment",
      "addiu"  -> "<operator>.assignment",
      "addu"   -> "<operator>.assignment",
      "and"    -> "<operator>.and",
      "andi"   -> "<operator>.and",
      "b"      -> "<operator>.goto",
      "bal"    -> "CALL",
      "beq"    -> "<operator>.goto",
      "beql"   -> "<operator>.goto",
      "bgez"   -> "<operator>.goto",
      "bgezl"  -> "<operator>.goto",
      "bne"    -> "<operator>.goto",
      "bnel"   -> "<operator>.goto",
      "j"      -> "<operator>.goto",
      "jal"    -> "CALL",
      "jalr"   -> "CALL",
      "jr"     -> "RETURN",
      "lb"     -> "<operator>.assignment",
      "lbu"    -> "<operator>.assignment",
      "lhu"    -> "<operator>.assignment",
      "li"     -> "<operator>.assignment",
      "lui"    -> "<operator>.assignment",
      "lw"     -> "<operator>.assignment",
      "lwl"    -> "<operator>.assignment",
      "lwr"    -> "<operator>.assignment",
      "nop"    -> "<operator>.NOP",
      "or"     -> "<operator>.or",
      "ori"    -> "<operator>.or",
      "sb"     -> "<operator>.assignment",
      "sll"    -> "<operator>.assignment",
      "sltu"   -> "<operator>.assignment",
      "sra"    -> "<operator>.assignment",
      "srl"    -> "<operator>.assignment",
      "subu"   -> "<operator>.assignment",
      "sw"     -> "<operator>.assignment"
    )
}

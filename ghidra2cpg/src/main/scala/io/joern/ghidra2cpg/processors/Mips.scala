package io.joern.ghidra2cpg.processors
import scala.collection.immutable._

class Mips extends Processor {
  override def getInstructions: HashMap[String, String] =
    HashMap(
      "_addiu" -> "<operator>.assignment",
      "_li"    -> "<operator>.assignment",
      "_lw"    -> "<operator>.assignment",
      "_nop"   -> "<operator>.NOP",
      "_or"    -> "<operator>.or",
      "_sw"    -> "<operator>.assignment",
      "addiu"  -> "<operator>.assignment",
      "addu"   -> "<operator>.assignment",
      "and"    -> "<operator>.and",
      "b"      -> "<operator>.goto",
      "bal"    -> "CALL",
      "beq"    -> "<operator>.goto",
      "bne"    -> "<operator>.goto",
      "jalr"   -> "CALL",
      "jr"     -> "RETURN",
      "lbu"    -> "<operator>.assignment",
      "li"     -> "<operator>.assignment",
      "lui"    -> "<operator>.assignment",
      "lw"     -> "<operator>.assignment",
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


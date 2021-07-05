package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class CFGTests extends GhidraCodeToCpgSuite {

  override val code: String =
    """
      | #include <stdio.h>
      | int main(int argc, char**argv) {printf("hello world");}
      |""".stripMargin

  "should have the cfgFirst node with the value set in" in {
    val cfgFirst = cpg.method.name("main").cfgFirst.l.head
    cfgFirst.code shouldBe "ENDBR64"
    cfgFirst.order shouldBe 0
  }
}

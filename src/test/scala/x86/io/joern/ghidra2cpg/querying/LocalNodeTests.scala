package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class LocalNodeTests extends GhidraCodeToCpgSuite {

  override val code: String =
    """
      | int main() {
      |  int x = 10;
      |}
      |""".stripMargin

  "should contain exactly one node with all mandatory fields set" in {
    cpg.method.name("main").local.l match {
      case List(x) =>
        x.name shouldBe "local_c"
        x.code shouldBe "[undefined4 local_c@Stack[-0xc]:4]"
        x.typeFullName shouldBe "undefined4"
      case _ => fail()
    }
  }
}

package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language._

class LocalNodeTests extends GhidraCodeToCpgSuite {

  override val code: String = ""

  "should contain exactly one node with all mandatory fields set" in {
    cpg.method.name("localNodeTests").local.l.head match {
      case x =>
        x.name shouldBe "local_c"
        x.code shouldBe "[undefined4 local_c@Stack[-0xc]:4]"
        x.typeFullName shouldBe "undefined4"
      case _ => fail()
    }
  }
}

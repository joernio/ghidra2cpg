package x86.io.joern.ghidra2cpg.querying

import io.shiftleft.semanticcpg.language.{ICallResolver, _}

class CallNodeTests extends GhidraCodeToCpgSuite {
  override val code: String =
    """
      | int level3() { return 1; }
      | int level2() { return level3(); }
      | int level1() { return level2(); }
      | int main() {
      |   int x = 10;
      |   return level1();
      |}
      |""".stripMargin

  "A call should contain exactly one node with all mandatory fields set" in {
    cpg.call
      .name("<operator>.assignment")
      .where(
        _.argument
          .order(2)
          .code("a")
      )
      .l match {
      case List(x) =>
        x.name shouldBe "<operator>.assignment"
      case _ => fail()
    }
  }

  "A method with name 'main' should have a call with the according code" in {
    cpg.method
      .name("main")
      .call
      .name("<operator>.assignment")
      .where(
        _.argument
          .order(2)
          .code("a")
      )
      .l match {
      case List(x) =>
        x.code shouldBe "MOV dword ptr [RBP + -0x4],0xa"
      case _ => fail()
    }
  }

  "A call should have a method with the name 'main' " in {
    cpg.call
      .name("<operator>.assignment")
      .where(_.argument.order(2).code("a"))
      .method
      .l match {
      case List(x) =>
        x.name shouldBe "main"
      case _ => fail()
    }
  }

  "The caller of the caller of 'level2' should be 'main' " in {
    implicit val resolver: ICallResolver = NoResolve
    val x = cpg.method
      .name("level2")
      .caller
      .caller
      .l
    x match {
      case List(x) =>
        x.name shouldBe "main"
      case _ => fail()
    }
  }

  "The method 'level2' should have a node with the name 'level1' " in {
    implicit val resolver: ICallResolver = NoResolve
    cpg.method
      .name("level2")
      .caller
      .l match {
      case List(x) =>
        x.name shouldBe "level1"
      case _ => fail()
    }
  }
}

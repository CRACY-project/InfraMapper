package plugins

trait Plugin {

  protected def internalRun(): Unit
  def checkPlugin(): Option[String]

  def run(): Unit = {
    val optCheck = checkPlugin()
    optCheck match {
      case None => internalRun()
      case Some(message) =>
        System.err.println(message)
        System.exit(1)
    }
  }
}

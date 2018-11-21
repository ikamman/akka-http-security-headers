import Dependencies._

lazy val root = (project in file(".")).
  settings(
    inThisBuild(List(
      organization := "com.github.ikamman.ahsh",
      scalaVersion := "2.12.7",
      version      := "0.1.0-SNAPSHOT"
    )),
    name := "akka-http-security-headers",
    libraryDependencies ++= Seq(
      akkaHttp % Provided,
      scalaTest % Test,
    ),
    scalacOptions += "-unchecked"
  )

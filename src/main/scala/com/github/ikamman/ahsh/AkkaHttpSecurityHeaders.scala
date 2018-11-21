package com.github.ikamman.ahsh

import akka.http.scaladsl.model.HttpHeader
import akka.http.scaladsl.model.headers.{ModeledCustomHeader, ModeledCustomHeaderCompanion}
import akka.http.scaladsl.server.Directive0
import akka.http.scaladsl.server.Directives._

import scala.util.Try

trait AkkaHttpSecurityHeaders {

  def respondWithDefaultSecurityHeaders: Directive0 = respondWithHeaders(
    XFrameOptionsHeader(Deny),
    XXSSProtectionHeader(EnabledWithBlockMode),
    XContentTypeOptionsHeader(NoSniff)
  )

  private[ahsh] sealed trait SecurityHeader[T] {
    def value: String
  }

  private[ahsh] trait ResponsesRendering extends HttpHeader {
    override def renderInResponses(): Boolean = true

    override def renderInRequests(): Boolean = false
  }

  private[ahsh] sealed trait RequestSecurityHeaderModel[T] extends SecurityHeader[T]

  private[ahsh] sealed trait ResponseSecurityHeaderModel[T] extends SecurityHeader[T]

  case class XFrameOptionsHeader(value: String) extends ModeledCustomHeader[XFrameOptionsHeader]
    with ResponsesRendering {
    override val companion: XFrameOptionsHeader.type = XFrameOptionsHeader
  }

  object XFrameOptionsHeader extends ModeledCustomHeaderCompanion[XFrameOptionsHeader] {
    override val name = "X-Frame-Options"

    override def parse(value: String) = Try(XFrameOptionsHeader(value))

    def apply(header: ResponseSecurityHeaderModel[XFrameOptionsHeader]) = new XFrameOptionsHeader(header.value)
  }

  case object Deny extends ResponseSecurityHeaderModel[XFrameOptionsHeader] {
    override def value: String = "DENY"
  }

  case object SameOrigin extends ResponseSecurityHeaderModel[XFrameOptionsHeader] {
    override def value: String = "SAMEORIGIN"
  }

  case class AllowFrom(uri: String) extends ResponseSecurityHeaderModel[XFrameOptionsHeader] {
    override def value: String = s"ALLOW-FROM $uri"
  }

  case class XXSSProtectionHeader(value: String) extends ModeledCustomHeader[XXSSProtectionHeader]
    with ResponsesRendering {
    override val companion: ModeledCustomHeaderCompanion[XXSSProtectionHeader] = XXSSProtectionHeader
  }

  object XXSSProtectionHeader extends ModeledCustomHeaderCompanion[XXSSProtectionHeader] {
    override def name: String = "X-XSS-Protection"

    override def parse(value: String): Try[XXSSProtectionHeader] = Try(XXSSProtectionHeader(value))

    def apply(header: ResponseSecurityHeaderModel[XXSSProtectionHeader]) = new XXSSProtectionHeader(header.value)
  }

  case object Disabled extends ResponseSecurityHeaderModel[XXSSProtectionHeader] {
    override def value: String = "0"
  }

  // Removing suspicious parts
  case object Enabled extends ResponseSecurityHeaderModel[XXSSProtectionHeader] {
    override def value: String = "1"
  }

  // Blocks rendering
  object EnabledWithBlockMode extends ResponseSecurityHeaderModel[XXSSProtectionHeader]{
    override def value: String = "1; mode=block"
  }

  // Reporting violation on the given url
  case class EnabledAndReport(uri: String) extends ResponseSecurityHeaderModel[XXSSProtectionHeader] {
    override def value: String = s"1; report=$uri"
  }

  case class XContentTypeOptionsHeader(value: String) extends ModeledCustomHeader[XContentTypeOptionsHeader]
    with ResponsesRendering {
    override val companion: ModeledCustomHeaderCompanion[XContentTypeOptionsHeader] = XContentTypeOptionsHeader
  }

  object XContentTypeOptionsHeader extends ModeledCustomHeaderCompanion[XContentTypeOptionsHeader] {
    override def name: String = "X-Content-Type-Options"

    override def parse(value: String): Try[XContentTypeOptionsHeader] = Try(XContentTypeOptionsHeader(value))

    def apply(header: ResponseSecurityHeaderModel[XContentTypeOptionsHeader]) = new XContentTypeOptionsHeader(header.value)
  }

  case object NoSniff extends ResponseSecurityHeaderModel[XContentTypeOptionsHeader] {
    override def value: String = "nosniff"
  }
}

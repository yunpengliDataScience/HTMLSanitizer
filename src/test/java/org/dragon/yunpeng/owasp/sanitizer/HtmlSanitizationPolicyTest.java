package org.dragon.yunpeng.owasp.sanitizer;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class HtmlSanitizationPolicyTest {

	@Test
    public void shouldNotAllowLinksOrJavaScriptOnStrictPolicy() {
        String text = "Text with <a href=\"https://example.com\">a link</a> " +
                "and<script>alert('javascript');</script>";

        String sanitized = new HtmlSanitizationPolicy("STRICT").sanitize(text);

        assertThat(sanitized).isEqualTo("Text with a link and");
    }

    @Test
    public void shouldNotAllowJavaScriptOnArticlePolicy() {
        String text = "Text with <a href=\"https://example.com\" rel=\"nofollow\">a link</a> " +
                "and<script>alert('javascript');</script>";

        String sanitized = new HtmlSanitizationPolicy("ARTICLE").sanitize(text);

        assertThat(sanitized).isEqualTo("Text with <a href=\"https://example.com\" rel=\"nofollow\">a link</a> and");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "A <h1>Title</h1> and a <p>paragraph</p>",
            "<strong>Strong</strong> and <em>emphasized</em>",
            "Code with <span style=\"color:red\">style</span>",
            "An <img src=\"https://example.com/img.jpg\" width=\"200\" />",
            "A <a href=\"https://example.com\" rel=\"nofollow\">link</a>"
    })
    public void shouldAllowCommonArticleElementsOnArticlePolicy(String text) {
        String sanitized = new HtmlSanitizationPolicy("ARTICLE").sanitize(text);

        assertThat(sanitized).isEqualTo(text);
    }

    @Test
    public void shouldNotAllowLinksOrJavaScriptOnCustomPolicy() {
        String text = "Text with <a href=\"https://example.com\" rel=\"nofollow\">a link</a> " +
                "and<script>alert('javascript');</script> and <my-element>Mine</my-element>";

        String sanitized = new HtmlSanitizationPolicy("CUSTOM").sanitize(text);

        assertThat(sanitized).isEqualTo("Text with a link and and <my-element>Mine</my-element>");
    }

    @Test
    public void shouldAllowMyElementOnCustomPolicy() {
        String text = "Text with <my-element>Mine</my-element>";

        String sanitized = new HtmlSanitizationPolicy("CUSTOM").sanitize(text);

        assertThat(sanitized).isEqualTo(text);
    }
}

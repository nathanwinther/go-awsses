package awsses

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/xml"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "time"
    "github.com/nathanwinther/go-uuid4"
)

type Message struct {
    From string
    To string
    Subject string
    Html string
    Text string
    Attachments []*MessageAttachment
}

type MessageAttachment struct {
    Content []byte
    ContentType string
    Name string
}

type sendRawEmailResponse struct {
    XMLName xml.Name `xml:"SendRawEmailResponse"`
}

func New(
    from string,
    to string,
    subject string,
    html string,
    text string,
    attachments ...*MessageAttachment) (*Message) {

    return &Message{from, to, subject, html, text, attachments}
}

func (m *Message) Bytes() ([]byte, error) {
    u, err := uuid4.New()
    if err != nil {
        return nil, err
    }

    boundary := fmt.Sprintf("_Part_0_%s", u)

    u, err = uuid4.New()
    if err != nil {
        return nil, err
    }

    var buf bytes.Buffer
    buf.WriteString(fmt.Sprintf("From: %s\n", m.From))
    buf.WriteString(fmt.Sprintf("To: %s\n", m.To))
    buf.WriteString(fmt.Sprintf("Subject: %s\n", m.Subject))
    buf.WriteString("MIME-Version: 1.0\n")
    buf.WriteString(fmt.Sprintf("Message-ID: <%s@message>\n", u))
    buf.WriteString("Content-Type: multipart/mixed;\n")
    buf.WriteString(fmt.Sprintf("\tboundary=\"%s\"\n\n", boundary))

    if m.Text != "" {
        buf.WriteString(fmt.Sprintf("--%s\n", boundary))
        buf.WriteString("Content-Type: text/plain; charset=\"us-ascii\"\n")
        buf.WriteString("Content-Transfer-Encoding: quoted-printable\n\n")
        buf.WriteString(fmt.Sprintf("%s\n\n", m.Text))
    }

    if m.Html != "" {
        buf.WriteString(fmt.Sprintf("--%s\n", boundary))
        buf.WriteString("Content-Type: text/html; charset=\"iso-8859-1\"\n")
        buf.WriteString("Content-Transfer-Encoding: quoted-printable\n\n")
        buf.WriteString(fmt.Sprintf("%s\n\n", m.Html))
    }

    for _, a := range m.Attachments {
        attachment := base64.StdEncoding.EncodeToString(a.Content)
        timestamp := time.Now().UTC().Format(time.RFC1123Z)
        buf.WriteString(fmt.Sprintf("--%s\n", boundary))
        buf.WriteString(fmt.Sprintf(
            "Content-Type: %s; name=\"%s\"\n", a.ContentType, a.Name))
        buf.WriteString(fmt.Sprintf("Content-Description: %s\n", a.Name))
        buf.WriteString(fmt.Sprintf(
            "Content-Disposition: attachment; filename=\"%s\"; size=%d;\n",
            a.Name, len(attachment)))
        buf.WriteString(fmt.Sprintf("\tcreation-date=\"%s\";\n", timestamp))
        buf.WriteString(fmt.Sprintf("\tmodification-date=\"%s\"\n", timestamp))
        buf.WriteString("Content-Transfer-Encoding: base64\n\n")
        buf.WriteString(fmt.Sprintf("%s\n\n", attachment))
    }

    buf.WriteString(fmt.Sprintf("--%s\n", boundary))

    return buf.Bytes(), nil
}

func (m *Message) Send(
    baseUrl string,
    accessKey string,
    secretKey string) error {

    message, err := m.Bytes()
    if err != nil {
        return err
    }

    timestamp := time.Now().UTC().Format(time.RFC1123Z)

    var post bytes.Buffer
    post.WriteString(fmt.Sprintf(
        "AWSAccessKeyId=%s",
        url.QueryEscape(accessKey)))
    post.WriteString("&Action=SendRawEmail")
    post.WriteString(fmt.Sprintf("&Timestamp=%s", url.QueryEscape(timestamp)))
    post.WriteString(fmt.Sprintf(
        "&RawMessage.Data=%s",
        url.QueryEscape(base64.StdEncoding.EncodeToString(message))))

    req, err := http.NewRequest("POST", baseUrl, &post)
    if err != nil {
        return err
    }

    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Add("Date", timestamp)
    req.Header.Add("X-Amzn-Authorization", m.sign(
        accessKey, secretKey, timestamp))

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    b, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return err
    }

    xmlresp := new(sendRawEmailResponse)
    err = xml.Unmarshal(b, xmlresp)
    if err != nil {
        return err
    }

    return nil
}

func (m *Message) sign(
    accessKey string,
    secretKey string,
    timestamp string) string {

    h := hmac.New(sha256.New, []byte(secretKey))
    h.Write([]byte(timestamp))

    return fmt.Sprintf(
        "AWS3-HTTPS AWSAccessKeyId=%s, Algorithm=HmacSHA256, Signature=%s",
        accessKey,
        base64.StdEncoding.EncodeToString(h.Sum(nil)))
}


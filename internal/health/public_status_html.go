package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	publicAPIsPageSize         = 50
	maxPublicHTMLBytes         = 2 * 1024 * 1024
	maxPublicHTMLRawQueryBytes = 1600
	maxPublicHTMLSearchBytes   = 256
	maxPublicHTMLSearchRunes   = 128
	maxPublicHTMLPage          = 10000
)

var (
	publicMetadataURLPattern        = regexp.MustCompile(`(?i)https?://[^\s<>"']+`)
	publicMetadataDomainPattern     = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:/[^\s]*)?`)
	publicMetadataCredentialPattern = regexp.MustCompile(`(?i)\b(?:service[_ -]?key|servicekey|api[_ -]?key|apikey|authorization)\s*[:=]\s*[^&\s<>"']+`)
	publicMetadataSensitivePattern  = regexp.MustCompile(`(?i)(?:secret|token|password|credential|bearer|service[_ -]?key|api[_ -]?key|authorization)`)
	publicInternalTargetPattern     = regexp.MustCompile(`(?i)\b(?:localhost|gatus|health-public|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{1,5})?\b`)
	publicStatusPages               = template.Must(template.New("status-pages").Funcs(template.FuncMap{"count": formatPublicCount}).Parse(publicStatusHTMLTemplate))
)

func formatPublicCount(value int) string {
	raw := strconv.Itoa(value)
	if value < 0 || len(raw) <= 3 {
		return raw
	}
	first := len(raw) % 3
	if first == 0 {
		first = 3
	}
	var output strings.Builder
	output.Grow(len(raw) + len(raw)/3)
	output.WriteString(raw[:first])
	for offset := first; offset < len(raw); offset += 3 {
		output.WriteByte(',')
		output.WriteString(raw[offset : offset+3])
	}
	return output.String()
}

const publicStatusHTMLTemplate = `<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{.PageTitle}}</title>
  <style>
    :root{color-scheme:light;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#152238;background:#f5f7fa;font-synthesis:none;text-rendering:optimizeLegibility}
    *{box-sizing:border-box}
    body{margin:0;line-height:1.55}
    main{max-width:900px;margin:0 auto;padding:24px 18px 56px}
    header{padding:12px 0 20px}
    nav{display:flex;flex-wrap:wrap;gap:8px 20px;border-bottom:1px solid #d6deea;padding:0 0 14px;margin:0 0 24px}
    a{color:#145bb8;text-underline-offset:3px}
    a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #145bb8;outline-offset:3px;border-radius:4px}
    h1{font-size:clamp(1.6rem,5vw,2.1rem);line-height:1.25;margin:0 0 10px;overflow-wrap:anywhere}
    h2{font-size:1.2rem;line-height:1.35;margin:0 0 12px}
    h3{font-size:1.05rem;line-height:1.4;margin:0 0 8px;overflow-wrap:anywhere}
    p{margin:8px 0;overflow-wrap:anywhere}
    .muted{color:#46556c}
    .notice{background:#eef4fb;border-left:4px solid #3069a6;padding:12px 14px;margin:18px 0;border-radius:4px}
    .warning{background:#fff5e8;border-left-color:#a45a00}
    .section{margin:22px 0}
    .readiness-compact{margin:8px 0 10px;padding:8px 12px}
    .readiness-compact h2{font-size:1rem;margin:0 0 4px}
    .readiness-compact p{margin:3px 0}
    .directory-scope{margin:8px 0 12px}
    .directory-scope-note{margin:4px 0;color:#46556c}
    .directory-list-heading{margin:0 0 10px}
    .directory-list-heading small{font-size:.78em;font-weight:500;color:#46556c}
    .directory-summary{display:flex;flex-wrap:wrap;gap:2px 16px;margin:6px 0}
    .directory-summary div{display:flex;flex-direction:row;gap:5px;align-items:baseline;border:0;padding:2px 0}
    .directory-summary dd{text-align:left}
    .directory-scope .directory-note{padding:7px 9px;margin:7px 0}
    .directory-scope .search{margin:8px 0 2px}
    .directory-details{margin:8px 0}
    .directory-details summary{cursor:pointer;font-weight:600}
    .directory-details[open]{padding:10px 12px}
    .summary{margin:0;padding:0}
    .summary div{display:flex;gap:8px;justify-content:space-between;align-items:baseline;border-bottom:1px solid #dce3ec;padding:8px 0}
    .summary dt{font-weight:600}
    .summary dd{margin:0;text-align:right;font-variant-numeric:tabular-nums}
    .search{display:flex;align-items:end;gap:10px;flex-wrap:wrap;margin:18px 0}
    .search label{display:block;font-weight:600;margin-bottom:5px}
    .search input{width:min(100%,560px);min-height:44px;border:1px solid #69788e;border-radius:6px;padding:8px 10px;font:inherit;background:#fff;color:inherit}
    button{min-height:44px;border:1px solid #124b93;border-radius:6px;background:#145bb8;color:white;padding:8px 15px;font:inherit;font-weight:600;cursor:pointer}
    .status-list{display:flex;flex-direction:column;gap:12px}
    .status-item{min-width:0;background:#fff;border:1px solid #d4dce7;border-radius:10px;padding:17px 18px;box-shadow:0 1px 2px #182b4410}
    .status-item p:last-child{margin-bottom:0}
    .metadata-state{display:inline-block;font-size:.875rem;color:#4d5a6e;margin-left:4px}
    .badge{display:inline-block;border:1px solid #8290a3;border-radius:999px;padding:2px 9px;font-size:.9rem;font-weight:650;white-space:normal}
    .badge-good{border-color:#23734a;color:#145c39;background:#edf8f1}
    .badge-warn{border-color:#966000;color:#704700;background:#fff7e6}
    .badge-bad{border-color:#a33b35;color:#842b26;background:#fff0ef}
    .badge-unknown{border-color:#687991;color:#394961;background:#f1f4f8}
    .pagination{display:flex;justify-content:space-between;gap:16px;align-items:center;margin:20px 0 0}
    .pagination a{padding:8px 12px;border:1px solid #8391a4;border-radius:6px;background:#fff}
    .operation-list{list-style:none;padding:0;margin:14px 0}
    .operation-list li{border-top:1px solid #dce3ec;padding:14px 0}
    .history-strip{display:flex;gap:4px;overflow-x:auto;list-style:none;padding:4px 0;margin:6px 0;max-width:100%}
    .history-point{flex:0 0 10px;width:10px;height:18px;border-radius:3px;border:1px solid #687991;background:#f1f4f8}
    .history-point-good{border-color:#23734a;background:#4c9b6b}
    .history-point-bad{border-color:#a33b35;background:#c95e58}
    time{font-variant-numeric:tabular-nums}
    footer{border-top:1px solid #d6deea;margin-top:32px;padding-top:16px;color:#46556c;font-size:.94rem}
    @media(max-width:480px){main{padding:14px 14px 36px}.status-item{padding:14px}.summary div{align-items:start;flex-direction:column;gap:0}.summary dd{text-align:left}.directory-summary div{align-items:baseline;flex-direction:row;gap:5px}.directory-summary dd{text-align:left}.pagination{align-items:stretch}.pagination a{max-width:48%}}
  </style>
</head>
<body>
<main>
  <header>
    <nav aria-label="주요 메뉴">
      <a href="/datapan/">API 목록</a>
      <a href="/datapan/dependencies/">검사 결과</a>
      <a href="/datapan/services/">관제 상태</a>
    </nav>
    <h1>{{.PageTitle}}</h1>
    {{if not .Directory}}<p>{{.Intro}}</p>{{end}}
  </header>
  {{if .SnapshotUnavailable}}<p class="notice warning" role="status">최근 결과를 불러오지 못했습니다. API 설명과 목록은 계속 볼 수 있지만, 기능별 상태는 확인할 수 없습니다.</p>{{end}}
  {{if .ServicesUnavailable}}<p class="notice warning" role="status">Datapan 서비스 상태를 확인할 수 없습니다. 잠시 후 다시 확인해 주세요.</p>{{end}}
  {{if .SelfReadiness}}
  <section class="status-item readiness-compact" aria-labelledby="self-readiness-heading">
      <h2 id="self-readiness-heading">Datapan 관제 <span class="badge {{.SelfReadiness.StatusClass}}">{{.SelfReadiness.StatusLabel}}</span></h2>
      <p>{{.SelfReadiness.Summary}}</p>
      <p class="muted">API 검사와 별도 · {{if .SelfReadiness.LastLoop}}관제 작업 <time datetime="{{.SelfReadiness.LastLoop.ISO}}" title="{{.SelfReadiness.LastLoop.FullKST}}">{{.SelfReadiness.LastLoop.Relative}}</time>{{else}}최근 관제 작업 기록 없음{{end}}</p>
  </section>
  {{end}}

  {{if .Directory}}
  <section class="directory-scope" aria-label="API 범위와 검사 결과">
    <p class="directory-scope-note">{{.ScopeNote}}</p>
    <dl class="summary directory-summary">
      <div><dt>API 정보</dt><dd>{{count .APIEntities}}개</dd></div>
      <div><dt>API 기능</dt><dd>{{count .APIOperations}}개</dd></div>
      <div><dt>최근 유효 결과</dt><dd>{{.RecentObservations}}</dd></div>
    </dl>
    <p class="notice warning directory-note">{{.ConfigNote}}</p>
    <form class="search" action="/datapan/" method="get" role="search">
    <div><label for="api-search">API 이름·기관·기능 검색</label><input id="api-search" name="q" type="search" maxlength="128" value="{{.SearchQuery}}" autocomplete="off"></div>
    <button type="submit">검색</button>
  </form>
  </section>
  <section class="section" aria-labelledby="api-list-heading">
    <h2 class="directory-list-heading" id="api-list-heading">API 목록 <small>{{.PageInfo}}</small></h2>
    <div class="status-list">
      {{range .APIs}}
      <article class="status-item">
        <h3>{{.Title}}</h3>
        <p><strong>기관:</strong> {{.Organization}}</p>
        <p><strong>기능:</strong> {{.Description}}</p>
        <p><strong>API 기능:</strong> {{count .APIOperations}}개 · <strong>외부 링크:</strong> {{count .LinkOperations}}개</p>
        <p><strong>검사 연결:</strong> {{count .ConfiguredOperations}}개 · <strong>검사 연결 전:</strong> {{count .UnconfiguredOperations}}개</p>
        <p><strong>최근 결과:</strong> {{.RecentObservations}}</p>
        {{if .LatestCheck}}<p><strong>최근 결과 수신:</strong> <time datetime="{{.LatestCheck.ISO}}" title="{{.LatestCheck.FullKST}}">{{.LatestCheck.Relative}}</time> · {{.LatestCheck.FullKST}}</p>{{end}}
        {{if .HistoryStart}}<p><strong>이력 시작:</strong> <time datetime="{{.HistoryStart.ISO}}" title="{{.HistoryStart.FullKST}}">{{.HistoryStart.FullKST}}</time></p>{{end}}
        {{if .ObservedOperations}}
        <p><strong>검사 연결된 기능:</strong></p>
        <ul class="operation-list">
          {{range .ObservedOperations}}<li><strong>{{.Name}}</strong> · <span class="badge {{.StatusClass}}">{{.ObservationLabel}}</span>{{if .LastObservation}}<br><strong>최근 결과 수신:</strong> <time datetime="{{.LastObservation.ISO}}" title="{{.LastObservation.FullKST}}">{{.LastObservation.Relative}}</time> · {{.LastObservation.FullKST}}{{end}}{{if .ResultLabel}}<br><strong>최근 검사 결과:</strong> {{.ResultLabel}}{{end}}{{if .IncidentLabel}}<br><strong>연속 결과 판정:</strong> {{.IncidentLabel}}{{end}}{{if .CauseLabel}}<br><strong>실패 분류:</strong> {{.CauseLabel}}{{end}}{{if .NextActionLabel}}<br><strong>다음 확인:</strong> {{.NextActionLabel}}{{end}}{{if .History}}<p class="muted">검사 결과 수신 이력 · 최근 {{len .History}}건</p><ol class="history-strip" aria-label="API 검사 결과 수신 이력">{{range .History}}<li class="history-point {{.Class}}" role="img" aria-label="{{.Label}} · {{.FullKST}}" title="{{.Label}} · {{.FullKST}}"></li>{{end}}</ol>{{end}}</li>{{end}}
        </ul>
        {{else}}<p class="muted">현재 검사 연결된 API 기능이 없습니다.</p>{{end}}
        <p><a href="{{.DetailURL}}">API와 기능별 검사 결과 보기</a></p>
      </article>
      {{else}}
      <p class="status-item">검색 결과가 없습니다. 다른 API 이름, 기관 또는 기능으로 검색해 보세요.</p>
      {{end}}
    </div>
    {{if .ShowPagination}}
    <nav class="pagination" aria-label="API 목록 페이지">
      {{if .PreviousURL}}<a href="{{.PreviousURL}}" rel="prev">이전 페이지</a>{{else}}<span></span>{{end}}
      <span>페이지 {{.PageNumber}} / {{.PageCount}}</span>
      {{if .NextURL}}<a href="{{.NextURL}}" rel="next">다음 페이지</a>{{else}}<span></span>{{end}}
    </nav>
    {{end}}
  </section>
  <details class="notice directory-details"><summary>전체 항목별 집계와 목록 기준</summary>
    <dl class="summary">
      <div><dt>API 기능</dt><dd>{{count .APIOperations}}개</dd></div>
      <div><dt>외부 링크</dt><dd>{{count .LinkOperations}}개</dd></div>
      <div><dt>제공 기관</dt><dd>{{count .Institutions}}곳</dd></div>
      <div><dt>검사 연결 전인 API 기능</dt><dd>{{count .UnconfiguredOperations}}개</dd></div>
      <div><dt>검사 연결됐지만 최근 결과가 없는 기능</dt><dd>{{.ConfiguredWithoutRecent}}</dd></div>
      <div><dt>API 기능 정보가 없는 등록 항목</dt><dd>{{count .OperationlessEntries}}개</dd></div>
      <div><dt>파일 자료 항목</dt><dd>{{count .FiledataEntries}}개</dd></div>
    </dl>
    <p>API 설명은 Datapan Registry에 저장된 고정된 원본 시점의 정보입니다. 최신 포털 등록 현황을 뜻하지 않습니다.</p>
    <p>API 설명 출처 revision: <code>{{.MetadataRevision}}</code></p>
    <p>검사 설정 revision: <code>{{.ObservationRevision}}</code></p>
    <p>{{.SortNote}}</p>
    <p>최근 결과 시각과 막대 이력은 Gatus 관제에 결과가 접수된 시각입니다. 원래 API 요청 시각과 다를 수 있습니다. 외부 링크는 API 기능 검사 수에 포함하지 않습니다.</p>
  </details>
  {{end}}

  {{if .Detail}}
  <section class="section" aria-labelledby="api-detail-heading">
    <article class="status-item">
      <h2 id="api-detail-heading">{{.DetailTitle}}</h2>
      <p><strong>기관:</strong> {{.DetailOrganization}}</p>
      <p><strong>기능:</strong> {{.DetailDescription}}</p>
      <p><strong>API 기능:</strong> {{.DetailAPIOperations}}개</p>
      <p><strong>외부 링크:</strong> {{.DetailLinkOperations}}개</p>
        <p><strong>검사 연결:</strong> {{.DetailConfigured}}개 · <strong>최근 결과:</strong> {{.DetailRecentObservations}}</p>
      <p class="muted">검사 결과는 연결된 개별 API 기능에만 표시합니다.</p>
    </article>
    {{if .DetailLinkOperations}}
    <p class="notice">이 API에는 외부 링크 {{.DetailLinkOperations}}개가 있습니다. 아래 API 기능 목록에는 REST 또는 SOAP 방식으로 제공되는 기능을 표시합니다.</p>
    {{end}}
    <h2>API 기능별 검사 결과</h2>
    <p class="muted">{{.OperationPageInfo}}</p>
    <ol class="operation-list">
      {{range .Operations}}
      <li class="status-item">
        <h3>{{.Name}}</h3>
        <p>제공 방식: {{.Protocol}} · {{.NameState}}</p>
        <p><strong>검사 결과:</strong> <span class="badge {{.StatusClass}}">{{.ObservationLabel}}</span></p>
        {{if .LastObservation}}<p><strong>최근 결과 수신:</strong> <time datetime="{{.LastObservation.ISO}}" title="{{.LastObservation.FullKST}}">{{.LastObservation.Relative}}</time> · {{.LastObservation.FullKST}}</p>{{end}}
        {{if .HistoryStart}}<p><strong>이력 시작:</strong> <time datetime="{{.HistoryStart.ISO}}" title="{{.HistoryStart.FullKST}}">{{.HistoryStart.FullKST}}</time></p>{{else}}<p><strong>이력 시작:</strong> 기록 없음</p>{{end}}
        {{if .ResultLabel}}<p><strong>최근 검사 결과:</strong> {{.ResultLabel}}</p>{{end}}
        {{if .IncidentLabel}}<p><strong>연속 결과 판정:</strong> {{.IncidentLabel}}</p>{{end}}
        {{if .CauseLabel}}<p><strong>확인된 사유:</strong> {{.CauseLabel}}</p>{{end}}
        {{if .NextActionLabel}}<p><strong>다음 확인:</strong> {{.NextActionLabel}}</p>{{end}}
        {{if .History}}<p class="muted">검사 결과 수신 이력 · 최근 {{len .History}}건</p><ol class="history-strip" aria-label="API 검사 결과 수신 이력">{{range .History}}<li class="history-point {{.Class}}" role="img" aria-label="{{.Label}} · {{.FullKST}}" title="{{.Label}} · {{.FullKST}}"></li>{{end}}</ol>{{end}}
      </li>
      {{else}}
      <li class="status-item">이 API에 등록된 REST·SOAP 기능이 없습니다.</li>
      {{end}}
    </ol>
    {{if .ShowPagination}}
    <nav class="pagination" aria-label="API 기능 페이지">
      {{if .PreviousURL}}<a href="{{.PreviousURL}}" rel="prev">이전 기능</a>{{else}}<span></span>{{end}}
      <span>페이지 {{.PageNumber}} / {{.PageCount}}</span>
      {{if .NextURL}}<a href="{{.NextURL}}" rel="next">다음 기능</a>{{else}}<span></span>{{end}}
    </nav>
    {{end}}
    <p><a href="/datapan/">API 목록으로 돌아가기</a></p>
  </section>
  {{end}}

  {{if .Dependencies}}
  <section class="section" aria-labelledby="dependency-heading">
    <h2 id="dependency-heading">검사 결과</h2>
    <p class="notice">{{.ConfigNote}}</p>
    <div class="status-list">
      {{range .DependencyRows}}
      <article class="status-item">
        <h3>{{.Title}}</h3>
        <p><strong>기관:</strong> {{.Organization}}</p>
        <p><strong>API 기능:</strong> {{.OperationName}}</p>
        <p><strong>기능:</strong> {{.Description}}</p>
        <p><strong>검사 결과:</strong> <span class="badge {{.StatusClass}}">{{.ObservationLabel}}</span></p>
        {{if .LastObservation}}<p><strong>최근 결과 수신:</strong> <time datetime="{{.LastObservation.ISO}}" title="{{.LastObservation.FullKST}}">{{.LastObservation.Relative}}</time> · {{.LastObservation.FullKST}}</p>{{end}}
        {{if .HistoryStart}}<p><strong>이력 시작:</strong> <time datetime="{{.HistoryStart.ISO}}" title="{{.HistoryStart.FullKST}}">{{.HistoryStart.FullKST}}</time></p>{{else}}<p><strong>이력 시작:</strong> 기록 없음</p>{{end}}
        {{if .ResultLabel}}<p><strong>최근 검사 결과:</strong> {{.ResultLabel}}</p>{{end}}
        {{if .IncidentLabel}}<p><strong>연속 결과 판정:</strong> {{.IncidentLabel}}</p>{{end}}
        {{if .CauseLabel}}<p><strong>확인된 사유:</strong> {{.CauseLabel}}</p>{{end}}
        {{if .NextActionLabel}}<p><strong>다음 확인:</strong> {{.NextActionLabel}}</p>{{end}}
        {{if .History}}<p class="muted">검사 결과 수신 이력 · 최근 {{len .History}}건</p><ol class="history-strip" aria-label="API 검사 결과 수신 이력">{{range .History}}<li class="history-point {{.Class}}" role="img" aria-label="{{.Label}} · {{.FullKST}}" title="{{.Label}} · {{.FullKST}}"></li>{{end}}</ol>{{end}}
        {{if .DetailURL}}<p><a href="{{.DetailURL}}">API와 기능별 결과 보기</a></p>{{end}}
      </article>
      {{end}}
    </div>
  </section>
  {{end}}

  {{if .Services}}
  <section class="section" aria-labelledby="service-heading">
    <article class="status-item">
      <h2 id="service-heading">Datapan 관제 상태</h2>
      <p>Datapan이 직접 제공하는 서비스 상태는 외부 공공데이터 API 검사 결과와 따로 표시합니다. 검증된 배포 근거가 없는 서비스는 미확인으로 둡니다.</p>
      <p><a href="/datapan/v1/services">기계 판독 관제 상태</a></p>
    </article>
    <div class="status-list">
      {{range .ServiceRows}}
      <article class="status-item">
        <h3>{{.Name}}</h3>
        <p><strong>상태:</strong> <span class="badge {{.StatusClass}}">{{.StatusLabel}}</span></p>
        {{if .Reason}}<p>{{.Reason}}</p>{{end}}
        {{if .RecordedAt}}<p><strong>상태 기록 시각:</strong> <time datetime="{{.RecordedAt.ISO}}" title="{{.RecordedAt.FullKST}}">{{.RecordedAt.FullKST}}</time></p>{{end}}
      </article>
      {{end}}
    </div>
  </section>
  {{end}}

  <footer>
    <p>기계 판독 상태: <a href="/datapan/v1/dependencies">검사 결과 JSON</a> · <a href="/datapan/v1/services">서비스 상태 JSON</a></p>
  </footer>
</main>
</body>
</html>`

type publicHTMLPage struct {
	PageTitle string
	Intro     string

	Directory    bool
	Detail       bool
	Dependencies bool
	Services     bool

	SnapshotUnavailable     bool
	ServicesUnavailable     bool
	SelfReadiness           *publicHTMLReadiness
	NotFound                bool
	MetadataRevision        string
	ObservationRevision     string
	ScopeNote               string
	ConfigNote              string
	APIEntities             int
	APIOperations           int
	LinkOperations          int
	FiledataEntries         int
	Institutions            int
	ConfiguredOperations    int
	RecentObservations      string
	UnconfiguredOperations  int
	ConfiguredWithoutRecent string
	OperationlessEntries    int

	SearchQuery    string
	PageInfo       string
	SortNote       string
	PageNumber     int
	PageCount      int
	ShowPagination bool
	PreviousURL    string
	NextURL        string
	APIs           []publicHTMLAPI

	DetailTitle              string
	DetailOrganization       string
	DetailDescription        string
	DetailAPIOperations      int
	DetailLinkOperations     int
	DetailConfigured         int
	DetailRecentObservations string
	OperationPageInfo        string
	Operations               []publicHTMLOperation
	DependencyRows           []publicHTMLOperation
	ServiceRows              []publicHTMLService
}

type publicHTMLService struct {
	Name        string
	StatusLabel string
	StatusClass string
	Reason      string
	RecordedAt  *publicHTMLTime
}

type publicHTMLReadiness struct {
	StatusLabel string
	StatusClass string
	Summary     string
	LastLoop    *publicHTMLTime
}

type publicHTMLHistoryPoint struct {
	Class   string
	Label   string
	FullKST string
}

type publicHTMLAPI struct {
	Title                  string
	Organization           string
	Description            string
	APIOperations          int
	LinkOperations         int
	ConfiguredOperations   int
	UnconfiguredOperations int
	RecentObservations     string
	LatestCheck            *publicHTMLTime
	HistoryStart           *publicHTMLTime
	ObservedOperations     []publicHTMLOperation
	DetailURL              string
}

type publicHTMLOperation struct {
	Name             string
	Protocol         string
	NameState        string
	ObservationLabel string
	StatusClass      string
	LastObservation  *publicHTMLTime
	HistoryStart     *publicHTMLTime
	ResultLabel      string
	IncidentLabel    string
	CauseLabel       string
	NextActionLabel  string
	History          []publicHTMLHistoryPoint
	Title            string
	Organization     string
	Description      string
	OperationName    string
	DetailURL        string
}

type publicHTMLTime struct {
	ISO      string
	FullKST  string
	Relative string
}

func (h *PublicStatusHandler) serveDatapanHTML(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writePublicHTMLError(w, r, http.StatusMethodNotAllowed)
		return
	}
	if h.registry == nil {
		writePublicHTMLError(w, r, http.StatusServiceUnavailable)
		return
	}
	request, parseStatus := parsePublicHTMLRequest(r)
	if parseStatus != http.StatusOK {
		writePublicHTMLError(w, r, parseStatus)
		return
	}
	statusDocument, statusErr := h.source.Snapshot(r.Context())
	statusAvailable := statusErr == nil
	if !statusAvailable {
		statusDocument = PublicStatusDocument{}
	}
	statusByOperation := publicStatusByRegistryOperation(*h.registry, statusDocument)
	now := time.Now().UTC()
	var readiness *publicHTMLReadiness
	if h.readiness != nil {
		self, selfErr := h.readiness.Snapshot(r.Context())
		readiness = projectPublicHTMLReadiness(self, selfErr == nil, now)
	}

	var page publicHTMLPage
	switch request.kind {
	case "directory":
		page = buildPublicHTMLDirectory(*h.registry, statusByOperation, statusAvailable, request, now)
	case "detail":
		api, found := h.registry.APIByID(request.apiID)
		if !found {
			writePublicHTMLError(w, r, http.StatusNotFound)
			return
		}
		page = buildPublicHTMLAPIDetail(*h.registry, api, statusByOperation, statusAvailable, request, now)
	case "dependencies":
		page = buildPublicHTMLDependencies(*h.registry, statusDocument, statusAvailable, now)
	case "services":
		serviceDocument, serviceErr := h.services.Snapshot(r.Context())
		page = buildPublicHTMLServices(serviceDocument, serviceErr == nil, now)
	default:
		writePublicHTMLError(w, r, http.StatusNotFound)
		return
	}
	page.SelfReadiness = readiness
	if page.NotFound {
		writePublicHTMLError(w, r, http.StatusNotFound)
		return
	}
	var output bytes.Buffer
	if err := publicStatusPages.Execute(&output, page); err != nil || output.Len() > maxPublicHTMLBytes {
		writePublicHTMLError(w, r, http.StatusServiceUnavailable)
		return
	}
	servePublicHTMLBytes(w, r, output.Bytes(), request.query != "")
}

func projectPublicHTMLReadiness(value HealthSelfReadiness, available bool, now time.Time) *publicHTMLReadiness {
	result := &publicHTMLReadiness{StatusLabel: "확인 실패", StatusClass: "badge-warn", Summary: "Datapan 관제 상태를 불러오지 못했습니다. API 기능 응답과 별개의 관제 문제입니다."}
	if !available {
		return result
	}
	if value.Ready && value.State == "ready" && value.Reason == "pipeline_current" {
		result.StatusLabel = "정상"
		result.StatusClass = "badge-good"
		result.Summary = "검사 작업과 결과 전달을 처리할 준비가 되어 있습니다."
	} else if value.State == "startup" {
		result.StatusLabel = "준비 중"
		result.StatusClass = "badge-warn"
		result.Summary = publicSelfReadinessReason(value.Reason)
	} else {
		result.StatusLabel = "점검 필요"
		result.StatusClass = "badge-bad"
		result.Summary = publicSelfReadinessReason(value.Reason)
	}
	if value.LastLoop != nil {
		lastLoop := publicHTMLTimeValue(*value.LastLoop, now)
		result.LastLoop = &lastLoop
	}
	return result
}

func publicSelfReadinessReason(reason string) string {
	switch reason {
	case "pipeline_current":
		return "검사 작업과 결과 전달을 처리할 준비가 되어 있습니다."
	case "awaiting_first_delivery":
		return "첫 검사 결과가 관제에 도착하기를 기다리고 있습니다."
	case "delivery_stale":
		return "일부 검사 결과 수신이 늦어지고 있습니다. 검사 일정과 결과 전달을 확인하세요."
	case "awaiting_first_loop":
		return "첫 관제 작업이 시작되기를 기다리고 있습니다."
	case "scheduler_loop_stale":
		return "관제 작업이 제때 완료되지 않았습니다. 스케줄러 상태를 확인하세요."
	case "scheduler_state_unavailable":
		return "관제 상태 저장소를 확인할 수 없습니다. 저장 경로와 권한을 확인하세요."
	case "runtime_dependencies_unavailable":
		return "검사 실행에 필요한 구성 요소를 확인할 수 없습니다. 설치와 설정을 확인하세요."
	case "delivery_failed":
		return "검사 결과를 관제에 전달하지 못했습니다. 결과 전달 경로를 확인하세요."
	case "cli_receipt_missing", "receipt_unavailable", "receipt_contract":
		return "검사 결과 기록을 확인할 수 없습니다. 검사 실행 로그와 기록 생성을 확인하세요."
	case "receipt_storage_unavailable":
		return "검사 결과 저장 위치를 사용할 수 없습니다. 저장소 상태와 권한을 확인하세요."
	default:
		return "관제 상태를 확인할 수 없습니다. 검사 일정과 결과 전달을 확인하세요."
	}
}

func buildPublicHTMLServices(document ServiceStatusDocument, available bool, now time.Time) publicHTMLPage {
	page := publicHTMLPage{PageTitle: "관제 상태", Intro: "Datapan이 직접 제공하는 서비스 상태를 API 검사 결과와 구분합니다.", Services: true, ServicesUnavailable: !available}
	if !available {
		return page
	}
	page.ServiceRows = make([]publicHTMLService, 0, len(document.Services))
	for _, service := range document.Services {
		row := publicHTMLService{Name: publicServiceDisplayName(service.ServiceID), StatusLabel: "미확인", StatusClass: "badge-unknown", Reason: publicServiceUnknownReason(service.UnknownReason)}
		if service.State == "operational" {
			row.StatusLabel, row.StatusClass, row.Reason = "정상 확인됨", "badge-good", ""
		} else if service.State == "degraded" {
			row.StatusLabel, row.StatusClass, row.Reason = "문제 확인", "badge-bad", ""
		}
		if !service.ObservedAt.IsZero() {
			value := publicHTMLTimeValue(service.ObservedAt, now)
			row.RecordedAt = &value
		}
		page.ServiceRows = append(page.ServiceRows, row)
	}
	return page
}

func publicServiceDisplayName(serviceID string) string {
	switch serviceID {
	case "dataset-api":
		return "Datapan 데이터 API"
	case "registry-distribution":
		return "Datapan Registry 배포"
	case "datapan-web-atlas":
		return "Datapan Web / Atlas"
	case "datapan-health":
		return "Datapan 관제"
	default:
		return "확인되지 않은 Datapan 서비스"
	}
}

func publicServiceUnknownReason(reason string) string {
	switch reason {
	case "deployment_identity_unavailable":
		return "검증된 배포 identity가 설정되지 않아 배포 상태를 확인할 수 없습니다."
	case "public_surface_unavailable":
		return "확인 가능한 공개 서비스 주소가 없습니다."
	case "configuration_unavailable":
		return "서비스 상태 확인 설정을 사용할 수 없습니다."
	default:
		return "서비스 상태를 확인할 근거가 없습니다."
	}
}

type publicHTMLRequest struct {
	kind  string
	apiID string
	page  int
	query string
}

func parsePublicHTMLRequest(r *http.Request) (publicHTMLRequest, int) {
	path := r.URL.Path
	directory := path == "/datapan/" || path == "/datapan/apis/"
	dependencies := path == "/datapan/dependencies/"
	services := path == "/datapan/services/"
	detail := strings.HasPrefix(path, "/datapan/apis/") && strings.HasSuffix(path, "/") && !directory
	if !directory && !dependencies && !services && !detail {
		return publicHTMLRequest{}, http.StatusNotFound
	}
	if len(r.URL.RawQuery) > maxPublicHTMLRawQueryBytes {
		return publicHTMLRequest{}, http.StatusBadRequest
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return publicHTMLRequest{}, http.StatusBadRequest
	}
	request := publicHTMLRequest{page: 1}
	allowed := map[string]bool{}
	if directory {
		request.kind = "directory"
		allowed["page"], allowed["q"] = true, true
	} else if detail {
		request.kind = "detail"
		allowed["page"] = true
		request.apiID = strings.TrimSuffix(strings.TrimPrefix(path, "/datapan/apis/"), "/")
		if !registryAPIIDPattern.MatchString(request.apiID) {
			return publicHTMLRequest{}, http.StatusNotFound
		}
	} else if dependencies {
		request.kind = "dependencies"
	} else {
		request.kind = "services"
	}
	for key, entries := range values {
		if !allowed[key] || len(entries) != 1 {
			return publicHTMLRequest{}, http.StatusBadRequest
		}
	}
	if rawPage := values.Get("page"); rawPage != "" {
		page, parseErr := strconv.Atoi(rawPage)
		if parseErr != nil || page < 1 || page > maxPublicHTMLPage {
			return publicHTMLRequest{}, http.StatusBadRequest
		}
		request.page = page
	}
	if rawQuery := values.Get("q"); rawQuery != "" {
		if !directory || !utf8.ValidString(rawQuery) || len(rawQuery) > maxPublicHTMLSearchBytes || utf8.RuneCountInString(rawQuery) > maxPublicHTMLSearchRunes || unsafePublicHTMLSearch(rawQuery) {
			return publicHTMLRequest{}, http.StatusBadRequest
		}
		for _, character := range rawQuery {
			if unicode.IsControl(character) {
				return publicHTMLRequest{}, http.StatusBadRequest
			}
		}
		request.query = strings.TrimSpace(rawQuery)
	}
	if (dependencies || services) && len(values) > 0 {
		return publicHTMLRequest{}, http.StatusBadRequest
	}
	return request, http.StatusOK
}

func buildPublicHTMLDirectory(metadata RegistryAPIMetadata, statusByOperation map[string]PublicOperationStatus, statusAvailable bool, request publicHTMLRequest, now time.Time) publicHTMLPage {
	const coverage = "data.go.kr 원본 시점의 Registry 목록입니다. 최신 포털이나 다른 제공처 전체 목록은 아닙니다."
	page := publicHTMLPage{
		PageTitle: "Datapan API 상태",
		Intro:     "기관별 API 기능과 검사 결과를 확인합니다.",
		Directory: true, SnapshotUnavailable: !statusAvailable, ScopeNote: coverage,
		APIEntities: metadata.Counts.APIEntities, APIOperations: metadata.Counts.APIOperations,
		LinkOperations: metadata.Counts.LinkOperations, FiledataEntries: metadata.Counts.FiledataCatalogEntries, Institutions: metadata.Counts.Institutions,
		ConfiguredOperations:   metadata.Counts.MatchedHealthCanaries,
		UnconfiguredOperations: max(0, metadata.Counts.APIOperations-metadata.Counts.MatchedHealthCanaries),
		OperationlessEntries:   metadata.Counts.OperationlessCatalogEntries,
		SearchQuery:            safePublicMetadataText(request.query), PageNumber: request.page,
		SortNote:         "현재 결과가 확인된 API를 먼저 표시합니다. 같은 그룹에서는 API 이름순입니다.",
		MetadataRevision: metadata.RegistryRevision, ObservationRevision: metadata.healthCatalogRevision,
	}
	page.ConfigNote = fmt.Sprintf("현재 검사 연결은 %s개 API 기능뿐입니다. 나머지 %s개 기능은 아직 검사 연결 전입니다.", formatPublicCount(page.ConfiguredOperations), formatPublicCount(page.UnconfiguredOperations))
	current := currentRegistryObservationCount(metadata, statusByOperation, statusAvailable)
	if current < 0 {
		page.RecentObservations = "자료 없음"
		page.ConfiguredWithoutRecent = "자료 없음"
	} else {
		page.RecentObservations = fmt.Sprintf("%s / %s개 연결 기능", formatPublicCount(current), formatPublicCount(metadata.Counts.MatchedHealthCanaries))
		page.ConfiguredWithoutRecent = fmt.Sprintf("%s / %s개 연결 기능", formatPublicCount(metadata.Counts.MatchedHealthCanaries-current), formatPublicCount(metadata.Counts.MatchedHealthCanaries))
	}
	priorityByAPI := make(map[string]int, len(metadata.HealthCanaryLinks))
	for _, link := range metadata.HealthCanaryLinks {
		priority := 1
		if status, ok := statusByOperation[link.RegistryOperationID]; statusAvailable && ok && status.ObservationState == "current" && status.ObservedAt != nil && (status.RawObservationState == "succeeded" || status.RawObservationState == "failed") {
			priority = 0
		}
		if current, exists := priorityByAPI[link.RegistryAPIID]; !exists || priority < current {
			priorityByAPI[link.RegistryAPIID] = priority
		}
	}
	items, total := metadata.APIPagePrioritized(request.query, request.page, publicAPIsPageSize, priorityByAPI)
	page.PageCount = pagesFor(total, publicAPIsPageSize)
	if page.PageCount == 0 {
		page.PageInfo = "검색 결과 0개"
	} else {
		start := (request.page-1)*publicAPIsPageSize + 1
		end := start + len(items) - 1
		page.PageInfo = fmt.Sprintf("%s개 중 %s–%s개 · 페이지 %d / %d", formatPublicCount(total), formatPublicCount(start), formatPublicCount(end), request.page, page.PageCount)
	}
	if page.PageCount > 0 && request.page > page.PageCount {
		page.NotFound = true
		return page
	}
	if page.PageCount == 0 && request.page > 1 {
		page.NotFound = true
		return page
	}
	page.ShowPagination = page.PageCount > 1
	if request.page > 1 {
		page.PreviousURL = directoryPageURL(request.query, request.page-1)
	}
	if request.page < page.PageCount {
		page.NextURL = directoryPageURL(request.query, request.page+1)
	}
	page.APIs = make([]publicHTMLAPI, 0, len(items))
	for _, api := range items {
		stats := apiObservationStats(metadata, api, statusByOperation, statusAvailable, now)
		apiRow := publicHTMLAPI{
			Title:         metadataFieldText(api.Title, api.TitleState, "API 이름"),
			Organization:  metadataFieldText(api.Organization, api.OrganizationState, "기관"),
			Description:   truncatePublicText(metadataFieldText(api.Description, api.DescriptionState, "기능 설명"), 320),
			APIOperations: len(api.Operations), LinkOperations: api.LinkOperationCount,
			ConfiguredOperations: stats.configured, UnconfiguredOperations: max(0, len(api.Operations)-stats.configured),
			RecentObservations: stats.recentText,
			LatestCheck:        stats.latestCheck, HistoryStart: stats.historyStart,
			DetailURL: buildPublicHTMLDirectoryAPIURL(api.RegistryAPIID),
		}
		for _, operation := range api.Operations {
			if _, linked := metadata.CanaryLinkByOperationID(operation.RegistryOperationID); linked {
				apiRow.ObservedOperations = append(apiRow.ObservedOperations, publicHTMLStatusRow(operation, metadata, statusByOperation, statusAvailable, now))
			}
		}
		page.APIs = append(page.APIs, apiRow)
	}
	return page
}

func buildPublicHTMLAPIDetail(metadata RegistryAPIMetadata, api RegistryAPIMetadataAPI, statusByOperation map[string]PublicOperationStatus, statusAvailable bool, request publicHTMLRequest, now time.Time) publicHTMLPage {
	stats := apiObservationStats(metadata, api, statusByOperation, statusAvailable, now)
	page := publicHTMLPage{
		PageTitle: "API 상세",
		Intro:     "등록된 API 기능과 실제 검사 결과를 각각 확인할 수 있습니다.",
		Detail:    true, SnapshotUnavailable: !statusAvailable,
		DetailTitle:         metadataFieldText(api.Title, api.TitleState, "API 이름"),
		DetailOrganization:  metadataFieldText(api.Organization, api.OrganizationState, "기관"),
		DetailDescription:   metadataFieldText(api.Description, api.DescriptionState, "기능 설명"),
		DetailAPIOperations: len(api.Operations), DetailLinkOperations: api.LinkOperationCount,
		DetailConfigured: stats.configured, DetailRecentObservations: stats.recentText,
		PageNumber:       request.page,
		MetadataRevision: metadata.RegistryRevision, ObservationRevision: metadata.healthCatalogRevision,
	}
	pageCount := pagesFor(len(api.Operations), publicAPIsPageSize)
	page.PageCount = pageCount
	if pageCount == 0 {
		page.OperationPageInfo = "등록된 API 기능이 없습니다."
	} else {
		start := (request.page-1)*publicAPIsPageSize + 1
		end := start + publicAPIsPageSize - 1
		if end > len(api.Operations) {
			end = len(api.Operations)
		}
		page.OperationPageInfo = fmt.Sprintf("API 기능 %s개 중 %s–%s개", formatPublicCount(len(api.Operations)), formatPublicCount(start), formatPublicCount(end))
	}
	if pageCount > 0 && request.page > pageCount {
		page.NotFound = true
		return page
	}
	if pageCount == 0 && request.page > 1 {
		page.NotFound = true
		return page
	}
	page.ShowPagination = pageCount > 1
	if request.page > 1 {
		page.PreviousURL = apiPageURL(api.RegistryAPIID, request.page-1)
	}
	if request.page < pageCount {
		page.NextURL = apiPageURL(api.RegistryAPIID, request.page+1)
	}
	start := (request.page - 1) * publicAPIsPageSize
	end := start + publicAPIsPageSize
	if end > len(api.Operations) {
		end = len(api.Operations)
	}
	if start < end {
		page.Operations = make([]publicHTMLOperation, 0, end-start)
		for _, operation := range api.Operations[start:end] {
			page.Operations = append(page.Operations, publicHTMLStatusRow(operation, metadata, statusByOperation, statusAvailable, now))
		}
	}
	return page
}

func buildPublicHTMLDependencies(metadata RegistryAPIMetadata, document PublicStatusDocument, statusAvailable bool, now time.Time) publicHTMLPage {
	page := publicHTMLPage{
		PageTitle:    "검사 결과",
		Intro:        "검사 연결된 API 기능의 최근 결과와 이력을 확인합니다.",
		Dependencies: true, SnapshotUnavailable: !statusAvailable,
		ConfiguredOperations: len(metadata.canaryDisplays),
		MetadataRevision:     metadata.RegistryRevision, ObservationRevision: metadata.healthCatalogRevision,
	}
	page.ConfigNote = fmt.Sprintf("현재 검사 연결은 %s개 API 기능뿐입니다. 나머지 %s개 기능은 아직 검사 연결 전입니다.", formatPublicCount(metadata.Counts.MatchedHealthCanaries), formatPublicCount(max(0, metadata.Counts.APIOperations-metadata.Counts.MatchedHealthCanaries)))
	statusesByHealthID := make(map[string]PublicOperationStatus, len(document.Operations))
	for _, status := range document.Operations {
		statusesByHealthID[status.OperationID] = status
	}
	displays := metadata.CanaryDisplays()
	page.DependencyRows = make([]publicHTMLOperation, 0, len(displays))
	for _, display := range displays {
		link, linked := metadata.CanaryLinkByHealthID(display.HealthOperationID)
		row := publicHTMLOperation{Name: safePublicMetadataText(display.OperationName), OperationName: safePublicMetadataText(display.OperationName)}
		if linked {
			api, apiOK := metadata.APIByID(link.RegistryAPIID)
			operation, operationOK := metadata.operationByID[link.RegistryOperationID]
			if apiOK && operationOK {
				row.Title = metadataFieldText(api.Title, api.TitleState, "API 이름")
				row.Organization = metadataFieldText(api.Organization, api.OrganizationState, "기관")
				row.Description = metadataFieldText(api.Description, api.DescriptionState, "기능 설명")
				row.OperationName = metadataFieldText(operation.Name, operation.NameState, "기능 이름")
				row.DetailURL = "/datapan/apis/" + url.PathEscape(api.RegistryAPIID) + "/"
			} else {
				row.Title = "API 이름을 확인할 수 없습니다"
				row.Organization = "기관 정보가 확인되지 않았습니다"
				row.Description = "이 검사 결과에 API 설명을 연결하지 못했습니다."
			}
		} else {
			row.Title = safePublicMetadataText(display.OperationName)
			row.Organization = "기관 정보를 연결하지 못했습니다"
			row.Description = "검사 결과는 유지되지만 API 이름·기관·기능 설명을 연결할 수 없습니다."
		}
		status, statusOK := statusesByHealthID[display.HealthOperationID]
		if statusOK {
			row = addPublicStatusLabels(row, status, now, statusAvailable)
		} else {
			row = addUnavailablePublicStatus(row, statusAvailable)
		}
		page.DependencyRows = append(page.DependencyRows, row)
	}
	return page
}

func publicStatusByRegistryOperation(metadata RegistryAPIMetadata, document PublicStatusDocument) map[string]PublicOperationStatus {
	statusesByHealthID := make(map[string]PublicOperationStatus, len(document.Operations))
	for _, status := range document.Operations {
		statusesByHealthID[status.OperationID] = status
	}
	statuses := make(map[string]PublicOperationStatus, len(metadata.HealthCanaryLinks))
	for _, link := range metadata.HealthCanaryLinks {
		if status, ok := statusesByHealthID[link.HealthOperationID]; ok {
			statuses[link.RegistryOperationID] = status
		}
	}
	return statuses
}

func currentRegistryObservationCount(metadata RegistryAPIMetadata, statusByOperation map[string]PublicOperationStatus, available bool) int {
	if !available {
		return -1
	}
	count := 0
	for _, link := range metadata.HealthCanaryLinks {
		if status, ok := statusByOperation[link.RegistryOperationID]; ok && status.ObservationState == "current" && status.ObservedAt != nil && (status.RawObservationState == "succeeded" || status.RawObservationState == "failed") {
			count++
		}
	}
	return count
}

type apiObservationSummary struct {
	configured   int
	recentText   string
	latestCheck  *publicHTMLTime
	historyStart *publicHTMLTime
}

func apiObservationStats(metadata RegistryAPIMetadata, api RegistryAPIMetadataAPI, statusByOperation map[string]PublicOperationStatus, statusAvailable bool, now time.Time) apiObservationSummary {
	configured, current := 0, 0
	var latest, earliest *time.Time
	for _, operation := range api.Operations {
		if _, linked := metadata.CanaryLinkByOperationID(operation.RegistryOperationID); !linked {
			continue
		}
		configured++
		if status, ok := statusByOperation[operation.RegistryOperationID]; ok && statusAvailable && status.ObservationState == "current" && status.ObservedAt != nil && (status.RawObservationState == "succeeded" || status.RawObservationState == "failed") {
			current++
		}
		if status, ok := statusByOperation[operation.RegistryOperationID]; ok && statusAvailable {
			if status.ObservedAt != nil && (latest == nil || status.ObservedAt.After(*latest)) {
				value := status.ObservedAt.UTC()
				latest = &value
			}
			if status.HistoryStartedAt != nil && (earliest == nil || status.HistoryStartedAt.Before(*earliest)) {
				value := status.HistoryStartedAt.UTC()
				earliest = &value
			}
		}
	}
	if !statusAvailable {
		return apiObservationSummary{configured: configured, recentText: "자료 없음"}
	}
	summary := apiObservationSummary{configured: configured, recentText: fmt.Sprintf("%s / %s개 연결", formatPublicCount(current), formatPublicCount(configured))}
	if latest != nil {
		value := publicHTMLTimeValue(*latest, now)
		summary.latestCheck = &value
	}
	if earliest != nil {
		value := publicHTMLTimeValue(*earliest, now)
		summary.historyStart = &value
	}
	return summary
}

func publicHTMLStatusRow(operation RegistryAPIMetadataOperation, metadata RegistryAPIMetadata, statuses map[string]PublicOperationStatus, statusAvailable bool, now time.Time) publicHTMLOperation {
	row := publicHTMLOperation{
		Name:     metadataFieldText(operation.Name, operation.NameState, "기능 이름"),
		Protocol: operation.Protocol, NameState: metadataStateLabel(operation.NameState),
	}
	if _, linked := metadata.CanaryLinkByOperationID(operation.RegistryOperationID); !linked {
		row.ObservationLabel, row.StatusClass = "검사 연결 전", "badge-unknown"
		return row
	}
	status, found := statuses[operation.RegistryOperationID]
	if !found {
		return addUnavailablePublicStatus(row, statusAvailable)
	}
	return addPublicStatusLabels(row, status, now, statusAvailable)
}

func addUnavailablePublicStatus(row publicHTMLOperation, statusAvailable bool) publicHTMLOperation {
	if !statusAvailable {
		row.ObservationLabel, row.StatusClass = "검사 결과를 불러오지 못함", "badge-warn"
		return row
	}
	row.ObservationLabel, row.StatusClass = "검사 연결됨 · 결과 기록 없음", "badge-unknown"
	return row
}

func addPublicStatusLabels(row publicHTMLOperation, status PublicOperationStatus, now time.Time, statusAvailable bool) publicHTMLOperation {
	if !statusAvailable {
		return addUnavailablePublicStatus(row, false)
	}
	switch status.ObservationState {
	case "current":
		switch status.RawObservationState {
		case "succeeded":
			row.ObservationLabel, row.StatusClass = "최근 검사 결과 통과", "badge-good"
		case "failed":
			row.ObservationLabel, row.StatusClass = "최근 검사 결과 실패", "badge-warn"
		default:
			row.ObservationLabel, row.StatusClass = "최근 검사 결과 상태 확인 필요", "badge-unknown"
		}
	case "stale":
		row.ObservationLabel, row.StatusClass = "최근 검사 결과가 오래됨", "badge-warn"
	case "not_observed":
		row.ObservationLabel, row.StatusClass = "검사 연결됨 · 결과 기록 없음", "badge-unknown"
	default:
		row.ObservationLabel, row.StatusClass = "결과 상태를 확인할 수 없음", "badge-unknown"
	}
	if status.ObservedAt != nil {
		observed := publicHTMLTimeValue(*status.ObservedAt, now)
		row.LastObservation = &observed
	}
	if status.HistoryStartedAt != nil {
		started := publicHTMLTimeValue(*status.HistoryStartedAt, now)
		row.HistoryStart = &started
	}
	if status.RawObservationState == "succeeded" {
		row.ResultLabel = "검사 결과 통과"
	} else if status.RawObservationState == "failed" {
		row.ResultLabel = "검사 결과 실패"
		row.StatusClass = "badge-bad"
		row.CauseLabel, row.NextActionLabel = publicHTMLDiagnosis(status.Diagnosis)
	}
	for _, point := range status.History {
		label, class := "검사 결과 수신 · 실패", "history-point-bad"
		if point.Success {
			label, class = "검사 결과 수신 · 통과", "history-point-good"
		}
		row.History = append(row.History, publicHTMLHistoryPoint{Class: class, Label: label, FullKST: publicHTMLTimeValue(point.ReceivedAt, now).FullKST})
	}
	switch status.IncidentState {
	case "pending":
		row.IncidentLabel = "연속 실패 기준 확인 중"
		row.ObservationLabel = "최근 검사 결과 실패 · 연속 기준 확인 중"
		if status.RawObservationState == "failed" {
			row.StatusClass = "badge-warn"
		}
	case "confirmed":
		row.IncidentLabel = "연속 실패 기준 충족"
		row.ObservationLabel = "최근 검사 결과 실패 · 연속 기준 충족"
		row.StatusClass = "badge-bad"
	case "recovering":
		row.IncidentLabel = "검사 결과 통과 후 연속 회복 확인 중"
		row.StatusClass = "badge-warn"
	case "operational":
		row.IncidentLabel = "연속 실패 기준에 도달하지 않음"
	}
	return row
}

func publicHTMLDiagnosis(diagnosis PublicDiagnosis) (cause, next string) {
	switch diagnosis.Code {
	case "approval_required":
		cause = "이 API 기능의 사용 승인이 필요할 수 있습니다."
	case "approval_propagating":
		cause = "사용 승인이 반영되는 중일 수 있습니다."
	case "credential_invalid":
		cause = "인증 정보와 사용 권한을 확인해야 합니다."
	case "invalid_input":
		cause = "요청에 필요한 입력값을 확인해야 합니다."
	case "rate_limited":
		cause = "요청 한도를 넘었을 수 있습니다."
	case "provider_outage":
		if diagnosis.Determination == "observed" {
			cause = "공급처 장애가 확인됐습니다."
		} else {
			cause = "공급처 장애로 추정됩니다."
		}
	case "contract_drift":
		cause = "API 응답 형식이 달라졌을 수 있습니다."
	case "semantic_quality":
		cause = "응답 내용의 품질을 확인해야 합니다."
	case "stale_data":
		cause = "응답 자료가 최신이 아닐 수 있습니다."
	default:
		cause = "현재 기록만으로는 실패 원인을 확인할 수 없습니다."
	}
	actionNames := map[string]string{
		"apply_for_operation":             "포털에서 API 기능 사용을 신청하세요.",
		"wait_for_approval_sync":          "승인 반영 후 다시 확인하세요.",
		"verify_credential_configuration": "인증 설정을 확인하세요.",
		"verify_request_parameters":       "요청 입력값을 확인하세요.",
		"retry_with_backoff":              "잠시 기다린 뒤 다시 확인하세요.",
		"check_provider_status":           "공급처 공지와 서비스 상태를 확인하세요.",
		"refresh_contract":                "최신 API 명세와 응답 형식을 확인하세요.",
		"inspect_data_quality":            "자료의 기준일과 응답 내용을 확인하세요.",
		"continue_to_reuse":               "현재 결과를 다시 사용할 수 있습니다.",
		"gather_more_evidence":            "추가 검사 결과를 기다리세요.",
	}
	for _, actionID := range diagnosis.RecommendedActionIDs {
		if label, ok := actionNames[actionID]; ok {
			return cause, label
		}
	}
	return cause, "추가 검사 결과와 공급처 공지, API 사용 조건을 확인하세요."
}

func buildPublicHTMLDirectoryAPIURL(apiID string) string {
	return "/datapan/apis/" + url.PathEscape(apiID) + "/"
}

func directoryPageURL(query string, page int) string {
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	if query != "" {
		values.Set("q", query)
	}
	return "/datapan/?" + values.Encode()
}

func apiPageURL(apiID string, page int) string {
	return buildPublicHTMLDirectoryAPIURL(apiID) + "?page=" + strconv.Itoa(page)
}

func pagesFor(items, pageSize int) int {
	if items <= 0 || pageSize <= 0 {
		return 0
	}
	return (items + pageSize - 1) / pageSize
}

func metadataFieldText(value, state, fieldLabel string) string {
	switch state {
	case "present", "sanitized":
		text := safePublicMetadataText(value)
		if state == "sanitized" {
			return text + " (안전 처리된 원문)"
		}
		return text
	case "missing":
		return fieldLabel + " 없음 (원본 미제공)"
	case "blank":
		return fieldLabel + " 없음 (원본이 비어 있음)"
	case "redacted_unsafe":
		return fieldLabel + "은 안전한 공개를 위해 생략했습니다"
	case "invalid_source":
		return fieldLabel + " 원문 검증이 필요합니다"
	default:
		return fieldLabel + " 정보를 확인할 수 없습니다"
	}
}

func metadataStateLabel(state string) string {
	switch state {
	case "present":
		return "원본 제공"
	case "sanitized":
		return "안전 처리된 원본"
	case "missing":
		return "원문 미제공"
	case "blank":
		return "원문 비어 있음"
	case "redacted_unsafe":
		return "안전상 생략"
	case "invalid_source":
		return "원문 검증 필요"
	default:
		return "상태 확인 필요"
	}
}

func safePublicMetadataText(value string) string {
	value = publicMetadataURLPattern.ReplaceAllString(value, "[외부 URL 생략]")
	value = publicMetadataCredentialPattern.ReplaceAllString(value, "[인증 값 생략]")
	value = publicInternalTargetPattern.ReplaceAllString(value, "[내부 주소 생략]")
	return strings.TrimSpace(value)
}

func unsafePublicHTMLSearch(value string) bool {
	lower := strings.ToLower(value)
	return publicMetadataURLPattern.MatchString(value) ||
		publicMetadataDomainPattern.MatchString(value) ||
		publicMetadataCredentialPattern.MatchString(value) ||
		publicMetadataSensitivePattern.MatchString(value) ||
		publicInternalTargetPattern.MatchString(value) ||
		strings.Contains(lower, "localhost") || strings.Contains(lower, "gatus") || strings.Contains(lower, "health-public") ||
		strings.ContainsAny(value, "/\\?&#=")
}

func truncatePublicText(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes]) + "…"
}

func publicHTMLTimeValue(value, now time.Time) publicHTMLTime {
	value = value.UTC()
	now = now.UTC()
	location, err := time.LoadLocation("Asia/Seoul")
	if err != nil {
		location = time.FixedZone("KST", 9*60*60)
	}
	delta := now.Sub(value)
	relative := "방금 전"
	switch {
	case delta < -30*time.Second:
		relative = "미래 시각 확인 필요"
	case delta >= 24*time.Hour:
		relative = fmt.Sprintf("%d일 전", int(delta.Hours()/24))
	case delta >= time.Hour:
		relative = fmt.Sprintf("%d시간 전", int(delta.Hours()))
	case delta >= time.Minute:
		relative = fmt.Sprintf("%d분 전", int(delta.Minutes()))
	}
	local := value.In(location)
	return publicHTMLTime{ISO: value.Format(time.RFC3339), FullKST: local.Format("2006-01-02 15:04 KST"), Relative: relative}
}

func servePublicHTMLBytes(w http.ResponseWriter, r *http.Request, body []byte, isSearch bool) {
	if len(body) > maxPublicHTMLBytes {
		writePublicError(w, http.StatusServiceUnavailable)
		return
	}
	cacheControl := "public, max-age=30, stale-if-error=60, no-transform"
	if isSearch {
		cacheControl = "no-store"
	}
	sum := sha256.Sum256(body)
	etag := `"sha256-` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Cache-Control", cacheControl)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func writePublicHTMLError(w http.ResponseWriter, r *http.Request, status int) {
	if status != http.StatusBadRequest && status != http.StatusNotFound && status != http.StatusMethodNotAllowed && status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
		status = http.StatusNotFound
	}
	title, message := "요청을 확인해 주세요", "요청한 페이지를 찾을 수 없습니다."
	switch status {
	case http.StatusBadRequest:
		message = "검색어나 페이지 값이 올바르지 않습니다. API 이름, 기관 또는 기능 설명으로 다시 검색해 주세요."
	case http.StatusMethodNotAllowed:
		message = "이 페이지는 읽기 전용입니다. 목록으로 돌아가 다시 확인해 주세요."
	case http.StatusTooManyRequests:
		title = "요청이 많습니다"
		message = "요청이 한꺼번에 들어와 목록을 잠시 불러올 수 없습니다. 1초 후 다시 시도해 주세요."
	case http.StatusServiceUnavailable:
		title = "상태 페이지를 불러올 수 없습니다"
		message = "상태 페이지를 잠시 사용할 수 없습니다. 잠시 후 다시 시도해 주세요."
	}
	body := "<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>" + template.HTMLEscapeString(title) + "</title></head><body><main style=\"font:16px system-ui;max-width:720px;margin:48px auto;padding:24px;color:#152238\"><h1>" + template.HTMLEscapeString(title) + "</h1><p>" + template.HTMLEscapeString(message) + "</p><p><a href=\"/datapan/\">API 목록으로 돌아가기</a></p></main></body></html>"
	if status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

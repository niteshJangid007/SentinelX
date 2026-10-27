# Working CRUD demonstration

Use your own local Sentinelx instance and a disposable project. The browser and API operate on the same PostgreSQL-backed records. This demonstration creates and deletes data in the signed-in workspace; use a synthetic demo account instead of a production workspace.

## Browser walkthrough

Start the application with `Start-Sentinelx.cmd` on Windows or `.venv/bin/python scripts/start.py`. Sign in, then choose **Repositories** from the top tabs or icon rail.

| Step | Action | Expected result |
| --- | --- | --- |
| Create | In the project creation form, enter `CRUD demonstration` in **Name**, then choose **Create project**. | A real project appears in the **Projects** table and becomes selectable for ZIP uploads. |
| Read | Choose **View project** on its row. Refresh the page and return to **Repositories**. | The stored project details remain available under the same account. |
| Update | Choose **Edit project**. Set **Project name**, **Description**, **Technology** and **Environment**, then choose **Save project**. | The table/details show the saved fields. A page reload preserves them. |
| Validate | Try to save a project name consisting only of spaces. | The request is rejected; the persisted project is not overwritten. |
| Delete | Choose **Delete project**, read the warning, tick **I understand and confirm**, then submit the destructive action. | The project and its related project data are removed. Audit history remains. The row disappears after a fresh read. |

The destructive submit remains disabled until confirmation is checked. Project deletion also deletes its connected repositories, scans, findings, deployment records and report history. Use a disposable project with no valuable scan history. Deletion cannot be undone through the UI.

Repository CRUD is available in **Connected repositories**. Connect an authorized public GitHub URL and branch, use **View repository** or **Edit repository**, then choose **Save repository**. **Disconnect repository** uses the same explicit confirmation checkbox. Disconnecting removes the connection but retains historical scans/findings/reports. A valid URL alone configures the connection; a completed scan establishes that the branch/archive is accessible.

Editing or deleting records related to a queued/running scan is rejected with a conflict (`409`). Wait for the scan to finish and retry. Viewer accounts have read-only details; write controls and server permissions do not grant them edits or deletions. Reading another account's project/repository by ID returns `404` rather than disclosing its existence.

## API contract

All routes below are relative to `/api/v1`. Authenticate first. Native clients can use the returned bearer token; the browser uses HttpOnly session cookies and matching same-origin write evidence.

| Operation | Request | Success |
| --- | --- | --- |
| Create project | `POST /projects` with `{name, description?, technology?, environment?}` | `201` with persisted project and ID. |
| List/search projects | `GET /projects?q=demo&limit=100&offset=0` | `200` with owner-scoped records. |
| Read project | `GET /projects/{id}` | `200`. |
| Update project | `PUT /projects/{id}` with project fields | `200` with saved fields. |
| Delete project | `DELETE /projects/{id}?confirm=true` | `204`, including project-data cascade. |
| Connect repository | `POST /repositories` with `{project_id, url, branch}` | `201`. |
| List/search repositories | `GET /repositories?q=owner&limit=100&offset=0` | `200`. |
| Read repository | `GET /repositories/{id}` | `200`. |
| Update repository | `PUT /repositories/{id}` with `{project_id, url, branch}` | `200`. |
| Disconnect repository | `DELETE /repositories/{id}?confirm=true` | `204`, preserving scan history. |

Search uses literal case-insensitive substrings, not SQL wildcard expressions. The API rejects unexpected fields, whitespace-only project names, invalid environments, unsupported GitHub hosts/URL forms and invalid branch references. `PUT` accepts the complete replacement form; fields omitted from a project update use their schema defaults.

Expected errors: missing deletion confirmation `422`; explicit `confirm=false` `400`; missing/foreign resource `404`; queued/running related work `409`; invalid request fields `422`; unauthenticated session `401`; insufficient write role `403`. Login throttling returns `429` with `Retry-After`.

## Repeatable native API example

Install `requirements.lock` and start the API first. Run this Python snippet only against your local instance. It creates a synthetic account and a disposable project, verifies create/read/update/validation/confirmation/delete, and prints no password or session value. The demo account and its audit events remain for inspection.

```python
import secrets
import uuid
import httpx

base = 'http://127.0.0.1:8000'
with httpx.Client(base_url=base, timeout=20) as client:
    registered = client.post('/api/v1/auth/register', json={
        'email': f'crud-{uuid.uuid4().hex}@example.test',
        'password': secrets.token_urlsafe(24),
    })
    registered.raise_for_status()
    client.headers['Authorization'] = 'Bearer ' + registered.json()['access_token']

    created = client.post('/api/v1/projects', json={
        'name': 'CRUD demonstration',
        'description': 'Disposable acceptance example',
        'technology': 'Python',
        'environment': 'development',
    })
    assert created.status_code == 201, created.text
    project = created.json()
    path = '/api/v1/projects/' + project['id']
    assert client.get(path).json()['name'] == 'CRUD demonstration'

    edited = client.put(path, json={
        'name': 'CRUD demonstration updated',
        'description': 'Saved through the API',
        'technology': 'Python',
        'environment': 'staging',
    })
    assert edited.status_code == 200, edited.text
    assert client.get(path).json()['environment'] == 'staging'
    assert client.get('/api/v1/projects', params={'q': 'updated'}).json()

    assert client.put(path, json={'name': '   '}).status_code == 422
    assert client.delete(path).status_code == 422
    assert client.delete(path, params={'confirm': 'false'}).status_code == 400
    assert client.get(path).status_code == 200
    assert client.delete(path, params={'confirm': 'true'}).status_code == 204
    assert client.get(path).status_code == 404
    print('CREATE, READ, UPDATE, validation, confirmation and DELETE verified.')
```

For the active-scan conflict demonstration, connect an authorized repository, start a scan and immediately try to edit/delete its repository or project. If the scan is still queued/running, expect `409` and unchanged data. Scan completion can be fast, so a manual attempt is timing-dependent; the deterministic API tests hold an active scan state and verify the conflict behavior. Do not start scans against resources you do not own or have permission to inspect.

## What to show a reviewer

Show the saved project before and after editing, a rejected invalid input, explicit deletion confirmation, disappearance after deletion, and retained audit evidence. Then create another disposable project and demonstrate a real ZIP or public GitHub scan and its downloaded report. A passing CRUD demo establishes the database workflow; it does not certify scanner completeness or create a public deployment.

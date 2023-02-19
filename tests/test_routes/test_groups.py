import datetime

import pytest

from auth_backend.exceptions import ObjectNotFound
from auth_backend.models.db import Group, UserGroup


def test_create(client, dbsession):
    time = datetime.datetime.utcnow()
    body = {"name": f"group{time}", "scopes": []}
    response_parent = client.post(url="/group", json=body)
    assert response_parent.status_code == 200
    parent_id = dbsession.query(Group).order_by(Group.id.desc()).first().id + 100
    res = client.post(url="/group", json={"name": f"group{time}", "parent_id": parent_id, "scopes": []})
    assert res.status_code == 404
    response_parent2 = client.post(url="/group", json=body)
    assert response_parent2.status_code == 409
    group = Group.get(response_parent.json()["id"], session=dbsession)
    assert group.id == response_parent.json()["id"]
    assert group.parent_id == response_parent.json()["parent_id"]
    assert group.name == response_parent.json()["name"]

    time = datetime.datetime.utcnow()
    body = {"name": f"group{time}", "parent_id": response_parent.json()["id"], "scopes": []}
    response = client.post(url="/group", json=body)
    assert response.status_code == 200
    group = Group.get(response.json()["id"], session=dbsession)
    assert group.id == response.json()["id"]
    assert group.parent_id == response.json()["parent_id"]
    assert group.name == response.json()["name"]

    parent = group.parent
    assert parent.id == response_parent.json()["id"]
    assert parent.parent_id == response_parent.json()["parent_id"]
    assert parent.name == response_parent.json()["name"]

    Group.delete(response.json()["id"], session=dbsession)
    Group.delete(response_parent.json()["id"], session=dbsession)
    dbsession.commit()


def test_get(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": group, "scopes": []}
    child = client.post(url="/group", json=body).json()["id"]
    response = client.get(f"/group/{group}")
    assert response.status_code == 200
    dbgroup = Group.get(group, session=dbsession)
    assert dbgroup.id == group
    assert dbgroup.name == response.json()["name"]
    assert dbgroup.parent_id == response.json()["parent_id"]
    assert dbgroup.id == response.json()["id"]
    response_child = client.get(f"/group/{child}")
    assert response_child.status_code == 200
    dbchild = Group.get(child, session=dbsession)
    assert dbchild.id == response_child.json()["id"]
    assert dbchild.name == response_child.json()["name"]
    assert dbchild.parent_id == group == response_child.json()["parent_id"]
    parent = dbchild.parent
    child_orm = dbgroup.child
    assert parent.id == dbgroup.id
    assert child_orm[0].id == dbchild.id

    for row in dbsession.query(Group).get(child), dbsession.query(Group).get(group):
        dbsession.delete(row)
    dbsession.commit()


def test_get_all(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": group, "scopes": []}
    child = client.post(url="/group", json=body).json()["id"]
    response = client.get("/group").json()["items"]
    assert group in [row["id"] for row in response]
    assert child in [row["id"] for row in response]

    for row in dbsession.query(Group).get(child), dbsession.query(Group).get(group):
        dbsession.delete(row)
    dbsession.commit()


def test_with_childs(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": group, "scopes": []}
    child = client.post(url="/group", json=body).json()["id"]
    response = client.get(f"/group/{group}", params={"info": ["child"]})
    assert response.status_code == 200
    assert child in [row["id"] for row in response.json()["child"]]

    response = client.get(f"/group/{child}", params={"info": ["child"]})
    assert response.status_code == 200
    assert group not in [row["id"] for row in response.json()["child"]]

    for row in dbsession.query(Group).get(child), dbsession.query(Group).get(group):
        dbsession.delete(row)
    dbsession.commit()


def test_patch(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    group = client.post(url="/group", json=body).json()["id"]
    response_old = client.get(f"/group/{group}")
    assert response_old.status_code == 200
    # db_old = Group.get(group, session=dbsession)
    time2 = datetime.datetime.utcnow()
    response_patch = client.patch(f"/group/{group}", json={"name": f"new_name{time2}"})
    assert response_patch.status_code == 200
    response_new = client.get(f"/group/{group}")
    assert response_new.status_code == 200
    db_new = Group.get(group, session=dbsession)
    assert response_patch.json()["id"] == response_new.json()["id"] == response_patch.json()["id"] == db_new.id
    assert response_patch.json()["name"] == response_new.json()["name"] == db_new.name
    assert (
        response_patch.json()["parent_id"]
        == response_new.json()["parent_id"]
        == response_patch.json()["parent_id"]
        == db_new.parent_id
    )
    assert response_old.json()["name"] != response_patch.json()["name"]
    dbsession.delete(dbsession.query(Group).get(group))
    dbsession.commit()


def test_cycle_patch(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    time2 = datetime.datetime.utcnow()
    group = client.post(url="/group", json=body).json()["id"]
    body2 = {"name": f"group{time2}", "parent_id": group, "scopes": []}
    group2 = client.post(url="/group", json=body2).json()["id"]
    response = client.patch(f"/group/{group}", json={"parent_id": group2})
    assert response.status_code == 400

    dbsession.query(UserGroup).delete()
    dbsession.query(Group).delete()
    dbsession.commit()


def test_delete(client, dbsession):
    time1 = datetime.datetime.utcnow()
    body = {"name": f"group{time1}", "parent_id": None, "scopes": []}
    _group1 = client.post(url="/group", json=body).json()["id"]
    time2 = datetime.datetime.utcnow()
    body = {"name": f"group{time2}", "parent_id": _group1, "scopes": []}
    _group2 = client.post(url="/group", json=body).json()["id"]
    time3 = datetime.datetime.utcnow()
    body = {"name": f"group{time3}", "parent_id": _group2, "scopes": []}
    _group3 = client.post(url="/group", json=body).json()["id"]
    db1 = Group.get(_group1, session=dbsession)
    db2 = Group.get(_group2, session=dbsession)
    db3 = Group.get(_group3, session=dbsession)
    assert db1.parent is None
    assert db3.parent == db2
    assert db2.parent == db1
    assert db2 in db1.child
    assert db3 in db2.child
    assert db3.child == []
    del db1
    del db2
    del db3
    response = client.get(f"/group/{_group3}")
    assert response.status_code == 200
    assert response.json()["parent_id"] == _group2
    response = client.get(f"/group/{_group2}")
    assert response.status_code == 200
    assert response.json()["parent_id"] == _group1
    client.delete(f"/group/{_group2}")
    response = client.get(f"/group/{_group3}")
    assert response.status_code == 200
    assert response.json()["parent_id"] == _group1
    db1 = Group.get(_group1, session=dbsession)
    with pytest.raises(ObjectNotFound):
        db2 = Group.get(_group2, session=dbsession)
    db3 = Group.get(_group3, session=dbsession)
    assert db3.parent == db1
    assert db3 in db1.child

    for row in (
        dbsession.query(Group).get(_group1),
        dbsession.query(Group).get(_group2),
        dbsession.query(Group).get(_group3),
    ):
        dbsession.delete(row)
    dbsession.commit()

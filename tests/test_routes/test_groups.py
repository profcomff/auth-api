import datetime

import pytest
import sqlalchemy.exc

from auth_backend.models.db import Group


def test_create(client, dbsession):
    time = datetime.datetime.utcnow()
    body = {"name": f"group{time}"}
    response_parent = client.post(url="/group", json=body)
    group = Group.get(response_parent.json()["id"], session=dbsession)
    assert group.id == response_parent.json()["id"]
    assert group.parent_id == response_parent.json()["parent_id"]
    assert group.name == response_parent.json()["name"]

    time = datetime.datetime.utcnow()
    body = {"name": f"group{time}", "parent_id": response_parent.json()["id"]}
    response = client.post(url="/group", json=body)
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


def test_get(client, dbsession, group):
    group = group(client, None)
    child = group(client, group)
    response = client.get(f"/group/{group}")
    dbgroup = Group.get(group, session=dbsession)
    assert dbgroup.id == group
    assert dbgroup.name == response.json()["name"]
    assert dbgroup.parent_id == response.json()["parent_id"]
    assert dbgroup.id == response.json()["id"]
    response_child = client.get(f"/group/{child}")
    dbchild = Group.get(child, session=dbsession)
    assert dbchild.id == response_child.json()["id"]
    assert dbchild.name == response.json()["name"]
    assert dbchild.parent_id == group == response.json()["parent_id"]
    parent = dbchild.parent
    child_orm = dbgroup.child
    assert parent == group
    assert child_orm == dbchild


def test_patch(client, dbsession, group):
    _group = group(client, None)
    response_old = client.get(f"/group/{group}")
    db_old = Group.get(group, session=dbsession)
    response_patch = client.patch(f"/group/{group}", json={"name": "new_name"})
    response_new = client.get(f"/group/{group}")
    db_new = Group.get(group, session=dbsession)
    assert response_patch.json()["id"] == response_new.json()["id"] == response_patch.json()["id"] == db_new.id == db_old.id
    assert response_patch.json()["name"] == response_new.json()["name"] == db_new.name
    assert response_patch.json()["parent_id"] == response_new.json()["parent_id"] == response_patch.json()["parent_id"] == db_new.parent_id
    assert response_old.json()["name"] == db_old.name != response_patch.json()["name"]


def test_delete(client, dbsession, group):
    _group1 = group(client, None)
    _group2 = group(client, _group1)
    _group3 = group(client, _group2)
    db1 = Group.get(_group1, session=dbsession)
    db2 = Group.get(_group2, session=dbsession)
    db3 = Group.get(_group3, session=dbsession)
    assert db1.parent is None
    assert db3.parent == db2
    assert db2.parent == db1
    assert db1.child == db2
    assert db2.child == db3
    assert db3.child is None
    response = client.get(f"/group/{_group3}")
    assert response.json()["parent_id"] == _group2
    response = client.get(f"/group/{_group2}")
    assert response.json()["parent_id"] == _group1
    client.delete(f"/group/{_group2}")
    response = client.get(f"/group/{_group3}")
    assert response.json()["parent_id"] == _group1
    db1 = Group.get(_group1, session=dbsession)
    with pytest.raises(sqlalchemy.exc.NoResultFound):
        db2 = Group.get(_group2, session=dbsession)
    db3 = Group.get(_group3, session=dbsession)
    assert db3.parent == db1
    assert db1.child == db3









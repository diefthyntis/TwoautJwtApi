package com.diefthyntis.TwoautJwtApi.model;



import jakarta.persistence.*;


/*
Tables that we define in models package will be automatically generated in Database.
If you check MySQL database for example, you can see things like this:

mysql> describe users;
+----------+--------------+------+-----+---------+----------------+
| Field    | Type         | Null | Key | Default | Extra          |
+----------+--------------+------+-----+---------+----------------+
| id       | bigint(20)   | NO   | PRI | NULL    | auto_increment |
| email    | varchar(50)  | YES  | UNI | NULL    |                |
| password | varchar(120) | YES  |     | NULL    |                |
| username | varchar(20)  | YES  | UNI | NULL    |                |
+----------+--------------+------+-----+---------+----------------+
4 rows in set (0.00 sec)

mysql> describe roles;
+-------+-------------+------+-----+---------+----------------+
| Field | Type        | Null | Key | Default | Extra          |
+-------+-------------+------+-----+---------+----------------+
| id    | int(11)     | NO   | PRI | NULL    | auto_increment |
| name  | varchar(20) | YES  |     | NULL    |                |
+-------+-------------+------+-----+---------+----------------+
2 rows in set (0.00 sec)

mysql> describe user_roles;
+---------+------------+------+-----+---------+-------+
| Field   | Type       | Null | Key | Default | Extra |
+---------+------------+------+-----+---------+-------+
| user_id | bigint(20) | NO   | PRI | NULL    |       |
| role_id | int(11)    | NO   | PRI | NULL    |       |
+---------+------------+------+-----+---------+-------+
2 rows in set (0.00 sec)
 */


@Entity
@Table(name = "role")
public class Role {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@Enumerated(EnumType.STRING)
	@Column(length = 20)
	private ERole name;

	public Role() {

	  }

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public ERole getName() {
		return name;
	}

	public void setName(ERole name) {
		this.name = name;
	}
	
	
}

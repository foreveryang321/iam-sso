package top.ylonline.easysso.oauth2.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.io.Serializable;

/**
 * @author yl
 */
@Data
@Entity(name = "t_user")
public class User implements Serializable {
    private static final long serialVersionUID = -1154448001776720487L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;

    private String password;
}

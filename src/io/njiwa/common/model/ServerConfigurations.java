package io.njiwa.common.model;

import org.hibernate.annotations.DynamicInsert;
import org.hibernate.annotations.DynamicUpdate;

import javax.persistence.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Entity
@Table(name="settings", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"item_name"}, name="settings_idx")
})
@SequenceGenerator(name="settings",sequenceName = "settings_seq",allocationSize = 1)
@DynamicInsert
@DynamicUpdate
public class ServerConfigurations {
    @javax.persistence.Id
    @Column(name = "id", unique = true, nullable = false, updatable = false)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "setting")
    private
    Long Id;

    @Column(name = "item_name", columnDefinition = "TEXT NOT NULL", nullable = false)
    private
    String name;

    @Column(name = "item_value", columnDefinition = "TEXT NOT NULL", nullable = false)
    private
    String value;


    public Long getId() {
        return Id;
    }

    public void setId(Long id) {
        Id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public static Map<String,String> load(EntityManager em)
    {
        Map<String,String> m = new HashMap<>();
        List<ServerConfigurations> sl = em.createQuery("from ServerConfigurations ",ServerConfigurations.class)
                .getResultList();
        for (ServerConfigurations s: sl)
            m.put(s.getName(),s.getValue());
        return  m;
    }

    public static void updateSetting(EntityManager em, String key, String value) {
        try {
            ServerConfigurations v = em.createQuery("from ServerConfigurations WHERE name = :k", ServerConfigurations.class)
                    .setParameter("k", key)
                    .getSingleResult();
            em.remove(v);
          //  em.flush();
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
        try {
            ServerConfigurations v = new ServerConfigurations();
            v.setName(key);
            v.setValue(value);
            em.persist(v);
        } catch (Exception ex) {
            String xs = ex.getMessage();
        }
    }
}

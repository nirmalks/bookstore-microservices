package com.nirmalks.checkout_service.order.repository;

import com.nirmalks.checkout_service.order.entity.Order;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {

	Page<Order> findAllByUserId(@Param("userId") Long userId, Pageable pageable);

}

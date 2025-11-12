package common;

import dto.PageRequestDto;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

public class RequestUtils {

	public static Pageable getPageable(PageRequestDto pageRequestDto) {
		return PageRequest.of(pageRequestDto.getPage(), pageRequestDto.getSize(),
				Sort.by(Sort.Order.by(pageRequestDto.getSortKey())
					.with(Sort.Direction.fromString(pageRequestDto.getSortOrder()))));
	}

}

// Add tests for ReturnStack for VecStack
#[cfg(test)]
use crate::types::stack::ReturnStack;
use crate::types::stack::StaticStack;

macro_rules! underflow_test {
    ($n:ident, $stack_type:ty) => {
        #[test]
        fn $n() {
            let mut s = <$stack_type>::new(2).unwrap();
            assert_eq!(s.pop(), None);
            assert_eq!(s.depth(), 0);

            s.push(10);
            s.pop();
            assert_eq!(s.pop(), None);
        }
    };
}

macro_rules! return_stack_implementation {
    ($n:ident, $stack_type:ty) => {
        #[test]
        fn $n() {
            let mut s = <$stack_type>::new(3).unwrap();
            s.push(1);
            s.push(2);
            s.push(3);
            assert_eq!(s.depth(), 3);
            assert_eq!(s.max_depth(), 3);

            s.push(4);
            assert_eq!(s.depth(), 3);
            assert_eq!(s.pop(), Some(4));
            assert_eq!(s.pop(), Some(3));
            assert_eq!(s.pop(), Some(2));
            assert_eq!(s.pop(), None);
        }
    };
}

underflow_test!(static_stack_under, StaticStack<2>);
return_stack_implementation!(static_implementation, StaticStack<3>);

#[cfg(feature = "alloc")]
mod box_stack_test {
    use super::*;
    use crate::types::stack::BoxStack;
    use crate::types::stack::ReturnStackBox;
    #[test]
    fn test_box_return_stack() {
        let mut box_stack = ReturnStackBox::new().unwrap();
        assert!(box_stack.pop().is_none(), "Expected box to be empty");
        box_stack.push(10);
        box_stack.push(555);
        box_stack.push(10000);

        assert_eq!(box_stack.pop(), Some(10000));
        assert_eq!(box_stack.pop(), Some(555));

        box_stack.push(35);
        assert_eq!(box_stack.pop(), Some(35));
        assert_eq!(box_stack.pop(), Some(10));
        assert_eq!(box_stack.pop(), None);
    }
}

    use crate::types::stack::VecStack;

    underflow_test!(vector_stack_under, VecStack);
    underflow_test!(box_stack_under, BoxStack);

    return_stack_implementation!(vector_implementation, VecStack);
    return_stack_implementation!(box_implmentation, BoxStack);
}

#[test]
fn none_return_static() {
    let s = StaticStack::<2>::new(3);
    assert!(s.is_none());
}
